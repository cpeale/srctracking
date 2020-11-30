use chrono::offset::Utc;
use chrono::DateTime;
use double_ratchet::Header;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use openssl::symm::{decrypt, encrypt, Cipher};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::vec::Vec;

//for tests
use rand_os::OsRng;
use std::time::{Duration, UNIX_EPOCH};

use crate::d_ratchet::*;

const FD_BOT: &[u8] = &[0; 352]; //signature size + tag size () + comm size (32) + rnd size (32) //TODO: Make the right length
const FD_SIZE: usize = 352;
const COMM_SIZE: usize = 32;
const RAND_SIZE: usize = 32;
const SRC_SIZE: usize = 32;
const SIG_SIZE: usize = 256;
const ID_SIZE: usize = 8;

pub fn make_comm<R: CryptoRng + RngCore>(msg: &[u8], rng: &mut R) -> (Vec<u8>, Vec<u8>) {
    let mut hasher = Sha256::new();
    let mut rnd = vec![0; 32]; //TODO: Should this be 32 or 64?\
    rng.fill_bytes(&mut rnd);
    hasher.input(msg);
    hasher.input(&rnd);
    let hash: Vec<u8> = hasher.result().as_slice().to_vec();
    return (rnd, hash);
}

pub fn check_comm(msg: &[u8], rnd: &[u8], comm: Vec<u8>) {
    let mut hasher = Sha256::new();
    hasher.input(msg);
    hasher.input(rnd);
    let hash: Vec<u8> = hasher.result().as_slice().to_vec();
    assert_eq!(&comm[..], &hash[..]);
}

pub struct Platform<'a> {
    sigkeys: PKey<openssl::pkey::Private>,
    symm_cipher: Cipher,
    symm_key: &'a [u8],
    symm_nonce: &'a [u8],
}

impl<'a> Platform<'a> {
    //constructor
    pub fn new() -> Platform<'a> {
        Platform {
            sigkeys: PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap(),
            symm_cipher: Cipher::aes_128_cbc(),
            symm_key: b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
            symm_nonce: b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07",
        }
    }

    //sign
    fn sign(&self, comm: &[u8], src: &[u8]) -> Vec<u8> {
        let mut signer = Signer::new(MessageDigest::sha256(), &self.sigkeys).unwrap();
        signer.update(comm).unwrap();
        signer.update(src).unwrap();
        signer.sign_to_vec().unwrap()
    }

    //sign with sha_512
    fn sign_512(&self, comm: &[u8], src: &[u8]) -> Vec<u8> {
        let mut signer = Signer::new(MessageDigest::sha512(), &self.sigkeys).unwrap();
        signer.update(comm).unwrap();
        signer.update(src).unwrap();
        signer.sign_to_vec().unwrap()
    }

    //sign with sha_384
    fn sign_384(&self, comm: &[u8], src: &[u8]) -> Vec<u8> {
        let mut signer = Signer::new(MessageDigest::sha384(), &self.sigkeys).unwrap();
        signer.update(comm).unwrap();
        signer.update(src).unwrap();
        signer.sign_to_vec().unwrap()
    }

    //check signature
    fn verify(&self, comm: &[u8], src: &[u8], signature: &[u8]) {
        let mut verifier = Verifier::new(MessageDigest::sha256(), &self.sigkeys).unwrap();
        verifier.update(comm).unwrap();
        verifier.update(src).unwrap();
        assert!(verifier.verify(&signature).unwrap());
    }

    //encrypt src + md
    fn make_tag(&self, userid: &[u8]) -> Vec<u8> {
        let d = std::time::SystemTime::now();
        let datetime: DateTime<Utc> = d.into();
        let md = datetime.timestamp();

        let tag = [userid.to_vec(), md.to_ne_bytes().to_vec()].concat();

        encrypt(self.symm_cipher, self.symm_key, Some(self.symm_nonce), &tag).unwrap()
    }

    //encrypt src + md
    fn make_tag_wo_md(&self, userid: &[u8]) -> Vec<u8> {
        encrypt(
            self.symm_cipher,
            self.symm_key,
            Some(self.symm_nonce),
            userid,
        )
        .unwrap()
    }

    //decrypt src + md
    pub fn extract_src(&self, src: &[u8]) -> Vec<u8> {
        decrypt(self.symm_cipher, self.symm_key, Some(self.symm_nonce), &src).unwrap()
    }

    pub fn process_send(&self, id: &[u8], comm: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let src = self.make_tag(id);
        let sig = self.sign(comm, &src);
        (sig, src)
    }

    pub fn process_send_wo_md(&self, id: &[u8], comm: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let src = self.make_tag_wo_md(id);
        let sig = self.sign(comm, &src);
        (sig, src)
    }

    pub fn process_send_wo_sig(&self, id: &[u8], comm: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let src = self.make_tag(id);
        let sig = vec![0; SIG_SIZE];
        (sig, src)
    }

    pub fn process_send_wo_tag(&self, id: &[u8], comm: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let src = vec![0; SRC_SIZE]; //DUMMY SRC
        let sig = self.sign(comm, &src);
        (sig, src)
    }

    pub fn process_send_sha_384(&self, id: &[u8], comm: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let src = self.make_tag(id);
        let sig = self.sign_384(comm, &src);
        (sig, src)
    }

    pub fn process_send_sha_512(&self, id: &[u8], comm: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let src = self.make_tag(id);
        let sig = self.sign_512(comm, &src);
        (sig, src)
    }
    

    pub fn process_report(&self, msg: Vec<u8>, fd: Vec<u8>) -> (u64, u64) {
        let (sig, rest3) = fd.split_at(SIG_SIZE);
        let (src, rest4) = rest3.split_at(SRC_SIZE);
        let (comm, rnd) = rest4.split_at(COMM_SIZE);

        //check commitment
        check_comm(&msg, rnd, comm.to_vec());

        //check author signature
        self.verify(comm, src, sig);

        let contents = self.extract_src(src);

        let (id, stamp) = contents.split_at(ID_SIZE);

        (
            u64::from_ne_bytes(id.try_into().unwrap()),
            u64::from_ne_bytes(stamp.try_into().unwrap()),
        )
    }
}

pub struct User {
    pub userid: Vec<u8>,
    pub msg_scheme: SignalDR,
}

impl User {
    pub fn new<R: CryptoRng + RngCore>(rng: &mut R) -> (User, User) {
        let mut rnd = vec![0; ID_SIZE]; //TODO: Length?
        rng.fill_bytes(&mut rnd);
        let mut rnd2 = vec![0; ID_SIZE]; //TODO: Length?
        rng.fill_bytes(&mut rnd2);

        let (user1, user2) = pair_setup();

        (
            User {
                userid: rnd,
                msg_scheme: user1,
            },
            User {
                userid: rnd2,
                msg_scheme: user2,
            },
        )
    }

    pub fn author<R: CryptoRng + RngCore>(
        &mut self,
        plaintext: &[u8],
        rng: &mut R,
    ) -> (Vec<u8>, (Header<PublicKey>, Vec<u8>)) {
        //println!("{:?}",plaintext.to_vec());

        let (rnd, hash) = make_comm(plaintext, rng);
        //make message:
        //should be: FD_BOT, hash, rnd, message
        let msg = [FD_BOT.to_vec(), hash.to_vec(), rnd, plaintext.to_vec()].concat();
        let e = self.msg_scheme.ratchet_encrypt(&msg, AD, rng);
        (hash, e)
    }

    pub fn fwd<R: CryptoRng + RngCore>(
        &mut self,
        plaintext: &[u8],
        fd: Vec<u8>,
        rng: &mut R,
    ) -> (Vec<u8>, (Header<PublicKey>, Vec<u8>)) {
        let (rnd, hash) = make_comm(plaintext, rng);
        //make message:
        //should be: fd, hash, rnd, message
        let msg = [fd, hash.to_vec(), rnd, plaintext.to_vec()].concat();
        let e = self.msg_scheme.ratchet_encrypt(&msg, AD, rng);
        (hash, e)
    }

    pub fn receive(
        &mut self,
        pd: (Vec<u8>, Vec<u8>, (Header<PublicKey>, Vec<u8>)),
        plat: &Platform,
    ) -> (Vec<u8>, Vec<u8>) {
        let (sig, src, (h, ct)) = pd;
        let pt = self.msg_scheme.ratchet_decrypt(&h, &ct, AD).unwrap();
        let (fd, rest) = pt.split_at(FD_SIZE);
        let (comm, rest2) = rest.split_at(COMM_SIZE);
        let (rnd, msg) = rest2.split_at(RAND_SIZE);

        //check commitment
        check_comm(msg, rnd, comm.to_vec());

        //check author signature
        plat.verify(comm, &src, &sig);

        if fd == FD_BOT {
            //println!("Received an authored message.");
            //println!("{:?}", msg);
            //println!("Contents: {:?}", String::from_utf8(msg.to_vec()).expect("Found invalid UTF-8"));
            (
                msg.to_vec(),
                [sig, src, comm.to_vec(), rnd.to_vec()].concat(),
            )
        } else {
            //println!("Received a forward.");
            //println!("{:?}", msg);
            //println!("Contents: {:?}", String::from_utf8(msg.to_vec()).expect("Found invalid UTF-8"));
            let (f_sig, rest3) = fd.split_at(SIG_SIZE);
            let (f_src, rest4) = rest3.split_at(SRC_SIZE);
            let (f_comm, f_rnd) = rest4.split_at(COMM_SIZE);
            //check commitment
            check_comm(msg, f_rnd, f_comm.to_vec());
            //check author signature
            plat.verify(f_comm, f_src, f_sig);

            (msg.to_vec(), fd.to_vec())
        }
    }
}

#[test]
fn basic_sha_tests() {
    //checking basic hash creation without random opening.
    let mut hasher = Sha256::new();
    let message = b"message to commit";

    hasher.input(message);
    let hash = hasher.result();

    let hash2 = Sha256::digest(message);
    assert_eq!(hash, hash2);

    let mut hasher3 = Sha256::new();
    hasher3.input(b"diff message");
    let hash3 = hasher3.result();

    assert_ne!(hash, hash3);

    //check converting to array
    let hash4 = Sha256::digest(message);
    let h4: [u8; 32] = hash4.as_slice().try_into().expect("Wrong length");
    let hash5 = Sha256::digest(message);
    let h5: [u8; 32] = hash5.as_slice().try_into().expect("Wrong length");
    assert_eq!(&h4[..], &h5[..]);
}

#[test]
fn basic_comm_test() {
    let mut rng = OsRng::new().unwrap();
    let msg = b"hello";
    let (r, c) = make_comm(msg, &mut rng);
    check_comm(msg, &r, c);
}

#[test]
fn basic_sig_test() {
    // Generate a keypair
    let keypair = Rsa::generate(2048).unwrap();
    let keypair = PKey::from_rsa(keypair).unwrap();

    let data = b"hello, world!";
    let data2 = b"hola, mundo!";

    // Sign the data
    let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
    signer.update(data).unwrap();
    signer.update(data2).unwrap();
    let signature = signer.sign_to_vec().unwrap();

    // Verify the data
    let mut verifier = Verifier::new(MessageDigest::sha256(), &keypair).unwrap();
    verifier.update(data).unwrap();
    verifier.update(data2).unwrap();
    assert!(verifier.verify(&signature).unwrap());
}

#[test]
fn basic_symm_key_test() {
    let cipher = Cipher::aes_128_cbc();
    let data = b"Crypto";
    let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
    let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";
    let ciphertext = encrypt(cipher, key, Some(iv), data).unwrap();

    let plaintext = decrypt(cipher, key, Some(iv), &ciphertext).unwrap();

    assert_eq!(data, &plaintext[..]);

    let data2 = b"New Crypto";
    let ciphertext2 = encrypt(cipher, key, Some(iv), data2).unwrap();

    let plaintext2 = decrypt(cipher, key, Some(iv), &ciphertext2).unwrap();

    assert_eq!(data2, &plaintext2[..]);
}

#[test]
fn auth_test() {
    let plaintext = b"Hellooooo";
    let mut rng = OsRng::new().unwrap();
    let plat = Platform::new();
    let (mut alice, mut bob) = User::new(&mut rng);
    //author message, from user
    let (comm, e) = alice.author(plaintext, &mut rng);
    //process message, from platform
    let (sig, src) = plat.process_send(&alice.userid, &comm);
    //receive message
    bob.receive((sig, src, e), &plat);
}

#[test]
fn fwd_test() {
    let plaintext = b"Hellooooo";
    let mut rng = OsRng::new().unwrap();
    let plat = Platform::new();
    let (mut alice, mut bob) = User::new(&mut rng);
    //author message, from user
    let (comm, e) = alice.author(plaintext, &mut rng);
    //process message, from platform
    let (sig, src) = plat.process_send(&alice.userid, &comm);
    //receive message
    let (_, fd) = bob.receive((sig, src, e), &plat);
    //forward message, from bob
    let (fcomm, fe) = bob.fwd(plaintext, fd, &mut rng);
    //process message, from platform
    let (fsig, fsrc) = plat.process_send(&bob.userid, &fcomm);
    alice.receive((fsig, fsrc, fe), &plat);
}

#[test]
fn report_test() {
    let plaintext = b"Hellooooo";
    let mut rng = OsRng::new().unwrap();
    let plat = Platform::new();
    let (mut alice, mut bob) = User::new(&mut rng);
    //author message, from user
    let (comm, e) = alice.author(plaintext, &mut rng);
    //process message, from platform
    let (sig, src) = plat.process_send(&alice.userid, &comm);
    //receive message
    let (msg, fd) = bob.receive((sig, src, e), &plat);
    //report message
    let (id, stamp) = plat.process_report(msg.to_vec(), fd);

    let d = UNIX_EPOCH + Duration::from_secs(stamp);
    let datetime = DateTime::<Utc>::from(d);
    let timestamp_str = datetime.format("%Y-%m-%d %H:%M:%S.%f").to_string();

    println!(
        "received valid report on the message {:?}",
        String::from_utf8(msg.to_vec()).expect("Found invalid UTF-8")
    );
    println!("Source user: {:?}, Send time: {}", id, timestamp_str);
}
