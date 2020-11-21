
use aes::{block_cipher_trait::BlockCipher, Aes256};
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use clear_on_drop::clear::Clear;
use double_ratchet::{self as dr, Header, KeyPair as _};
use generic_array::{typenum::U32, GenericArray};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{CryptoRng, RngCore};
use rand_os::OsRng;
use sha2::{Digest, Sha256};
use std::fmt;
use std::hash::{Hash, Hasher};
use subtle::ConstantTimeEq;
use x25519_dalek::{self, SharedSecret};

pub type SignalDR = dr::DoubleRatchet<SignalCryptoProvider>;
pub type HmacSha256 = Hmac<Sha256>;

pub struct SignalCryptoProvider;

impl dr::CryptoProvider for SignalCryptoProvider {
    type PublicKey = PublicKey;
    type KeyPair = KeyPair;
    type SharedSecret = SharedSecret;

    type RootKey = SymmetricKey;
    type ChainKey = SymmetricKey;
    type MessageKey = SymmetricKey;

    fn diffie_hellman(us: &KeyPair, them: &PublicKey) -> SharedSecret {
        us.private.diffie_hellman(&them.0)
    }

    fn kdf_rk(rk: &SymmetricKey, s: &SharedSecret) -> (SymmetricKey, SymmetricKey) {
        let salt = Some(rk.0.as_slice());
        let ikm = s.as_bytes();
        let prk = Hkdf::<Sha256>::extract(salt, ikm);
        let info = &b"WhisperRatchet"[..];
        let mut okm = [0; 64];
        prk.expand(&info, &mut okm).unwrap();
        let rk = GenericArray::<u8, U32>::clone_from_slice(&okm[..32]);
        let ck = GenericArray::<u8, U32>::clone_from_slice(&okm[32..]);
        (SymmetricKey(rk), SymmetricKey(ck))
    }

    fn kdf_ck(ck: &SymmetricKey) -> (SymmetricKey, SymmetricKey) {
        let key = ck.0.as_slice();
        let mut mac = Hmac::<Sha256>::new_varkey(key).unwrap();
        mac.input(&[0x01]);
        let mk = mac.result_reset().code();
        mac.input(&[0x02]);
        let ck = mac.result().code();
        (SymmetricKey(ck), SymmetricKey(mk))
    }

    fn encrypt(key: &SymmetricKey, pt: &[u8], ad: &[u8]) -> Vec<u8> {
        let ikm = key.0.as_slice();
        let prk = Hkdf::<Sha256>::extract(None, ikm);
        let info = b"WhisperMessageKeys";
        let mut okm = [0; 80];
        prk.expand(info, &mut okm).unwrap();
        let ek = GenericArray::<u8, <Aes256 as BlockCipher>::KeySize>::from_slice(&okm[..32]);
        let mk = GenericArray::<u8, <Hmac<Sha256> as Mac>::OutputSize>::from_slice(&okm[32..64]);
        let iv = GenericArray::<u8, <Aes256 as BlockCipher>::BlockSize>::from_slice(&okm[64..]);

        let cipher = Cbc::<Aes256, Pkcs7>::new_fix(ek, iv);
        let mut ct = cipher.encrypt_vec(pt);

        let mut mac = Hmac::<Sha256>::new_varkey(mk).unwrap();
        mac.input(ad);
        mac.input(&ct);
        let tag = mac.result().code();
        ct.extend((&tag[..8]).into_iter());

        okm.clear();
        ct
    }

    fn decrypt(key: &SymmetricKey, ct: &[u8], ad: &[u8]) -> Result<Vec<u8>, dr::DecryptError> {
        let ikm = key.0.as_slice();
        let prk = Hkdf::<Sha256>::extract(None, ikm);
        let info = b"WhisperMessageKeys";
        let mut okm = [0; 80];
        prk.expand(info, &mut okm).unwrap();
        let dk = GenericArray::<u8, <Aes256 as BlockCipher>::KeySize>::from_slice(&okm[..32]);
        let mk = GenericArray::<u8, <Hmac<Sha256> as Mac>::OutputSize>::from_slice(&okm[32..64]);
        let iv = GenericArray::<u8, <Aes256 as BlockCipher>::BlockSize>::from_slice(&okm[64..]);

        let ct_len = ct.len() - 8;
        let mut mac = Hmac::<Sha256>::new_varkey(mk).unwrap();
        mac.input(ad);
        mac.input(&ct[..ct_len]);
        let tag = mac.result().code();
        if bool::from(!(&tag.as_ref()[..8]).ct_eq(&ct[ct_len..])) {
            okm.clear();
            return Err(dr::DecryptError::DecryptFailure);
        }

        let cipher = Cbc::<Aes256, Pkcs7>::new_fix(dk, iv);
        if let Ok(pt) = cipher.decrypt_vec(&ct[..ct_len]) {
            okm.clear();
            Ok(pt)
        } else {
            okm.clear();
            Err(dr::DecryptError::DecryptFailure)
        }
    }
}

#[derive(Clone, Debug)]
pub struct PublicKey(x25519_dalek::PublicKey);

impl Eq for PublicKey {}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state);
    }
}

impl<'a> From<&'a x25519_dalek::StaticSecret> for PublicKey {
    fn from(private: &'a x25519_dalek::StaticSecret) -> PublicKey {
        PublicKey(x25519_dalek::PublicKey::from(private))
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

pub struct KeyPair {
    private: x25519_dalek::StaticSecret,
    public: PublicKey,
}

impl fmt::Debug for KeyPair {
    #[cfg(debug_assertions)]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "KeyPair {{ private (bytes): {:?}, public: {:?} }}",
            self.private.to_bytes(),
            self.public
        )
    }

    #[cfg(not(debug_assertions))]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "KeyPair {{ private (bytes): <hidden bytes>, public: {:?} }}",
            self.public
        )
    }
}

impl dr::KeyPair for KeyPair {
    type PublicKey = PublicKey;

    fn new<R: CryptoRng + RngCore>(rng: &mut R) -> KeyPair {
        let private = x25519_dalek::StaticSecret::new(rng);
        let public = PublicKey::from(&private);
        KeyPair { private, public }
    }

    fn public(&self) -> &PublicKey {
        &self.public
    }
}

#[derive(Default)]
pub struct SymmetricKey(pub GenericArray<u8, U32>);

impl fmt::Debug for SymmetricKey {
    #[cfg(debug_assertions)]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SymmetricKey({:?})", self.0)
    }

    #[cfg(not(debug_assertions))]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SymmetricKey(<hidden bytes>)")
    }
}

impl Drop for SymmetricKey {
    fn drop(&mut self) {
        self.0.clear();
    }
}

