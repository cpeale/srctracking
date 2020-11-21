//extern crate rand;
//use std::io;
use aes::{block_cipher_trait::BlockCipher, Aes256};
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use clear_on_drop::clear::Clear;
use double_ratchet::{self as dr, KeyPair as _, Header};
use generic_array::{typenum::U32, GenericArray};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{CryptoRng, RngCore};
use rand_os::OsRng;
use sha2::{Sha256, Digest};
use std::fmt;
use std::hash::{Hash, Hasher};
use subtle::ConstantTimeEq;
use x25519_dalek::{self, SharedSecret};

//added later
use std::time::{Duration, Instant};
use std::convert::TryInto;
use openssl::sign::{Signer, Verifier};
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use openssl::symm::{encrypt, decrypt, Cipher};
use std::vec::Vec;
use chrono::offset::Utc;
use chrono::DateTime;
use std::time::{SystemTime, UNIX_EPOCH};

//modules
mod d_ratchet;
use crate::d_ratchet::*;

#[test]
fn signal_session() {
    let mut rng = OsRng::new().unwrap();
    let (ad_a, ad_b) = (b"A2B:SessionID=42", b"B2A:SessionID=42");

    // Copy some values (these are usually the outcome of an X3DH key exchange)
    let bobs_prekey = KeyPair::new(&mut rng);
    let bobs_public_prekey = bobs_prekey.public().clone();
    let shared = SymmetricKey(GenericArray::<u8, U32>::clone_from_slice(
        b"Output of a X3DH key exchange...",
    ));

    // Alice fetches Bob's prekey bundle and completes her side of the X3DH handshake
    let mut alice = SignalDR::new_alice(&shared, bobs_public_prekey, None, &mut rng);
    // Alice creates her first message to Bob
    let pt_a_0 = b"Hello Bob";
    let (h_a_0, ct_a_0) = alice.ratchet_encrypt(pt_a_0, ad_a, &mut rng);
    // Alice creates an initial message containing `h_a_0`, `ct_a_0` and other X3DH information

    // Bob receives the message and finishes his side of the X3DH handshake
    let mut bob = SignalDR::new_bob(shared, bobs_prekey, None);
    // Bob can now decrypt the initial message
    assert_eq!(
        Ok(Vec::from(&b"Hello Bob"[..])),
        bob.ratchet_decrypt(&h_a_0, &ct_a_0, ad_a)
    );
    // Bob is now fully initialized: both sides can send and receive message

    let pt_a_1 = b"I will send this later";
    let (h_a_1, ct_a_1) = alice.ratchet_encrypt(pt_a_1, ad_a, &mut rng);
    let pt_b_0 = b"My first reply";
    let (h_b_0, ct_b_0) = bob.ratchet_encrypt(pt_b_0, ad_b, &mut rng);
    assert_eq!(
        Ok(Vec::from(&pt_b_0[..])),
        alice.ratchet_decrypt(&h_b_0, &ct_b_0, ad_b)
    );
    let pt_a_2 = b"What a boring conversation";
    let (h_a_2, _ct_a_2) = alice.ratchet_encrypt(pt_a_2, ad_a, &mut rng);
    let pt_a_3 = b"Don't you agree?";
    let (h_a_3, ct_a_3) = alice.ratchet_encrypt(pt_a_3, ad_a, &mut rng);
    assert_eq!(
        Ok(Vec::from(&pt_a_3[..])),
        bob.ratchet_decrypt(&h_a_3, &ct_a_3, ad_a)
    );

    let pt_b_1 = b"Agree with what?";
    let (h_b_1, ct_b_1) = bob.ratchet_encrypt(pt_b_1, ad_b, &mut rng);
    assert_eq!(
        Ok(Vec::from(&pt_b_1[..])),
        alice.ratchet_decrypt(&h_b_1, &ct_b_1, ad_b)
    );

    assert_eq!(
        Ok(Vec::from(&pt_a_1[..])),
        bob.ratchet_decrypt(&h_a_1, &ct_a_1, ad_a)
    );

    // No resending (that key is already deleted)
    assert!(bob.ratchet_decrypt(&h_a_1, &ct_a_1, ad_a).is_err());
    // No fake messages
    assert!(bob
        .ratchet_decrypt(&h_a_2, b"Incorrect ciphertext", ad_a)
        .is_err());
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
    let ciphertext = encrypt(
        cipher,
        key,
        Some(iv),
        data).unwrap();

    let plaintext = decrypt(
            cipher,
            key,
            Some(iv),
            &ciphertext).unwrap();
        
    assert_eq!(
            data,
            &plaintext[..]);   


    let data2 = b"New Crypto";
    let ciphertext2 = encrypt(
        cipher,
        key,
        Some(iv),
        data2).unwrap();
        
    let plaintext2 = decrypt(
        cipher,
        key,
        Some(iv),
        &ciphertext2).unwrap();
                
    assert_eq!(
        data2,
        &plaintext2[..]);   
}

fn pair_setup() -> (SignalDR, SignalDR) {
    let mut rng = OsRng::new().unwrap();

    // Copy some values (these are usually the outcome of an X3DH key exchange)
    let bobs_prekey = KeyPair::new(&mut rng);
    let bobs_public_prekey = bobs_prekey.public().clone();
    let shared = SymmetricKey(GenericArray::<u8, U32>::clone_from_slice(
        b"Output of a X3DH key exchange...",
    ));

    // Alice fetches Bob's prekey bundle and completes her side of the X3DH handshake
    let mut alice = SignalDR::new_alice(&shared, bobs_public_prekey, None, &mut rng);
    // Alice creates her first message to Bob
    let pt_a_0 = b"Hello Bob";
    let (h_a_0, ct_a_0) = alice.ratchet_encrypt(pt_a_0, AD, &mut rng);
    // Alice creates an initial message containing `h_a_0`, `ct_a_0` and other X3DH information

    // Bob receives the message and finishes his side of the X3DH handshake
    let mut bob = SignalDR::new_bob(shared, bobs_prekey, None);
    // Bob can now decrypt the initial message
    assert_eq!(
        Ok(Vec::from(&b"Hello Bob"[..])),
        bob.ratchet_decrypt(&h_a_0, &ct_a_0, AD)
    );
    // Bob is now fully initialized: both sides can send and receive message
    return (alice, bob);
}

fn make_comm<R: CryptoRng + RngCore>(msg: &[u8], rng: &mut R) -> (Vec<u8>, Vec<u8>) {
    let mut hasher = Sha256::new();
    let mut rnd = vec![0; 32]; //TODO: Should this be 32 or 64?\
    rng.fill_bytes(&mut rnd);
    hasher.input(msg);
    hasher.input(&rnd);
    let hash: Vec<u8> = hasher.result().as_slice().to_vec();
    return (rnd, hash);
}

fn check_comm(msg: &[u8], rnd: &[u8], comm:Vec<u8>) {
    let mut hasher = Sha256::new();
    hasher.input(msg);
    hasher.input(rnd);
    let hash: Vec<u8> = hasher.result().as_slice().to_vec();
    assert_eq!(&comm[..], &hash[..]);
}

struct Platform<'a> {
    sigkeys:PKey<openssl::pkey::Private>,
    symm_cipher:Cipher,
    symm_key: &'a [u8],
    symm_nonce: &'a [u8],
}

impl<'a> Platform<'a> {
    //constructor
    pub fn new() -> Platform<'a> {
        Platform {
            sigkeys:PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap(),
            symm_cipher:Cipher::aes_128_cbc(),
            symm_key:b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F", 
            symm_nonce:b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07",
        }
    }

    //sign
    fn sign(&self, comm: &[u8], src: &[u8]) -> Vec<u8> {
        let mut signer = Signer::new(MessageDigest::sha256(), &self.sigkeys).unwrap();
        signer.update(comm).unwrap();
        signer.update(src).unwrap();
        signer.sign_to_vec().unwrap()
    }

    //check signature
    fn verify(&self, comm: &[u8], src: &[u8], signature:&[u8]) {
        let mut verifier = Verifier::new(MessageDigest::sha256(), &self.sigkeys).unwrap();
        verifier.update(comm).unwrap();
        verifier.update(src).unwrap();
        assert!(verifier.verify(&signature).unwrap());
    }

    //encrypt src + md
    fn make_tag(&self, userid:&[u8]) -> Vec<u8> {
        let d = std::time::SystemTime::now();
        let datetime: DateTime<Utc> = d.into();
        let md = datetime.timestamp();

        let tag = [userid.to_vec(), md.to_ne_bytes().to_vec()].concat();

        encrypt(
            self.symm_cipher,
            self.symm_key,
            Some(self.symm_nonce),
            &tag).unwrap()
    }

    //decrypt src + md
    fn extract_src(&self, src:&[u8]) -> Vec<u8> {
        //TODO: add metadata
        decrypt(
            self.symm_cipher,
            self.symm_key,
            Some(self.symm_nonce),
            &src).unwrap()
    } 

    fn process_send(&self, id:&[u8], comm:&[u8]) -> (Vec<u8>, Vec<u8>) {
        let src = self.make_tag(id);
        let sig = self.sign(comm, &src);
        (sig, src)
    }

    fn process_report(&self, msg: Vec<u8>, fd: Vec<u8>) -> (u64, u64) {
        let (sig, rest3) = fd.split_at(SIG_SIZE);
        let (src, rest4) = rest3.split_at(SRC_SIZE);
        let (comm, rnd) = rest4.split_at(COMM_SIZE);
            
        //check commitment
        check_comm(&msg, rnd, comm.to_vec());
        
        //check author signature
        self.verify(comm, src, sig); 

        let contents = self.extract_src(src);

        let (id, stamp) = contents.split_at(ID_SIZE);
    
        (u64::from_ne_bytes(id.try_into().unwrap()), u64::from_ne_bytes(stamp.try_into().unwrap()))
    }

}

struct User {
    userid:Vec<u8>,
    msg_scheme: SignalDR,
}

impl User {
    pub fn new<R: CryptoRng + RngCore>(rng: &mut R) -> (User, User) {
        let mut rnd = vec![0; ID_SIZE]; //TODO: Length?
        rng.fill_bytes(&mut rnd);
        let mut rnd2 = vec![0; ID_SIZE]; //TODO: Length?
        rng.fill_bytes(&mut rnd2);

        let (user1, user2) = pair_setup();

        (User {
            userid: rnd,
            msg_scheme: user1,
        }, 
        User {
            userid: rnd2,
            msg_scheme: user2,
        })
    }

    fn author<R: CryptoRng + RngCore>(&mut self, plaintext:&[u8], rng: &mut R) -> (Vec<u8>, (Header<PublicKey>, Vec<u8>)) {
        let (rnd, hash) = make_comm(plaintext, rng);
        //make message:
        //should be: FD_BOT, hash, rnd, message
        let msg = [FD_BOT.to_vec(), hash.to_vec(), rnd, plaintext.to_vec()].concat();
        let e = self.msg_scheme.ratchet_encrypt(&msg, AD, rng);
        (hash, e)
    }

    fn fwd<R: CryptoRng + RngCore>(&mut self, plaintext:&[u8], fd: Vec<u8>, rng: &mut R) -> (Vec<u8>, (Header<PublicKey>, Vec<u8>)) {
        let (rnd, hash) = make_comm(plaintext, rng);
        //make message:
        //should be: fd, hash, rnd, message
        let msg = [fd, hash.to_vec(), rnd, plaintext.to_vec()].concat();
        let e = self.msg_scheme.ratchet_encrypt(&msg, AD, rng);
        (hash, e)
    }

    fn receive(&mut self, pd: (Vec<u8>, Vec<u8>, (Header<PublicKey>, Vec<u8>)), plat: &Platform) -> (Vec<u8>, Vec<u8>){
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
            //println!("Contents: {:?}", String::from_utf8(msg.to_vec()).expect("Found invalid UTF-8"));
            (msg.to_vec(), [sig, src, comm.to_vec(), rnd.to_vec()].concat())
        } else {
            //println!("Received a forward.");
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

    println!("received valid report on the message {:?}", String::from_utf8(msg.to_vec()).expect("Found invalid UTF-8"));
    println!("Source user: {:?}, Send time: {}", id, timestamp_str);
}


const AD:&[u8] = b"ad";
const FD_BOT:&[u8] = &[0;352]; //signature size + tag size () + comm size (32) + rnd size (32) //TODO: Make the right length
const FD_SIZE: usize = 352;
const COMM_SIZE: usize = 32;
const RAND_SIZE: usize = 32;
const SRC_SIZE: usize = 32;
const SIG_SIZE: usize = 256;
const ID_SIZE: usize = 8;

fn time_traceback(length: usize, iters: u64) {
    //let plaintext = b"Hellooooo";
    let mut rng = OsRng::new().unwrap();
    let plat = Platform::new();
    let (mut alice, mut bob) = User::new(&mut rng);
    let mut plaintext = vec![0; length]; 
        rng.fill_bytes(&mut plaintext);

    let mut auth_sum = 0;
    let mut proc_sum = 0;
    let mut rec_sum = 0;
    let mut fwd_sum = 0;
    let mut rec_fwd_sum = 0;
    let mut rep_sum = 0;
    let mut total_auth_sum = 0;
    let mut total_fwd_sum = 0;

    for _ in 1..iters {
        //author
        let mut start = Instant::now();
        let (comm, e) = alice.author(&plaintext, &mut rng);
        let duration_send = start.elapsed();
        
        //process
        start = Instant::now();
        let (sig, src) = plat.process_send(&alice.userid, &comm);
        let duration_proc = start.elapsed();

        //receive author
        start = Instant::now();
        let (msg, fd) = bob.receive((sig, src, e), &plat);
        let duration_rec = start.elapsed();

        //report
        start = Instant::now();
        plat.process_report(msg.to_vec(), fd.to_vec());
        let duration_rep = start.elapsed();

        //fwd
        start = Instant::now();
        let (comm, e) = bob.fwd(&plaintext, fd, &mut rng);
        let duration_fwd = start.elapsed();

        let (sig, src) = plat.process_send(&bob.userid, &comm);

        //receive forward
        start = Instant::now();
        alice.receive((sig, src, e), &plat);
        let duration_rec_fwd = start.elapsed();

        //total time for author
        start = Instant::now();
        let (comm, e) = alice.author(&plaintext, &mut rng);
        let (sig, src) = plat.process_send(&alice.userid, &comm);
        let (_, fd) = bob.receive((sig, src, e), &plat);
        let duration_total_auth = start.elapsed();

        //total time for forward
        start = Instant::now();
        let (comm, e) = bob.fwd(&plaintext, fd, &mut rng);
        let (sig, src) = plat.process_send(&bob.userid, &comm);
        alice.receive((sig, src, e), &plat);
        let duration_total_fwd = start.elapsed();


        auth_sum = auth_sum + duration_send.as_nanos();
        proc_sum = proc_sum + duration_proc.as_nanos();
        rec_sum = rec_sum + duration_rec.as_nanos();
        fwd_sum = fwd_sum + duration_fwd.as_nanos();
        rec_fwd_sum = fwd_sum + duration_rec_fwd.as_nanos();
        rep_sum = rep_sum + duration_rep.as_nanos();
        total_auth_sum = total_auth_sum + duration_total_auth.as_nanos();
        total_fwd_sum = total_fwd_sum + duration_total_fwd.as_nanos();
    }

    let denom = iters as f64 * 1000000.0;
    let auth_avg = auth_sum as f64/denom;
    let proc_avg = proc_sum as f64/denom;
    let rec_avg = rec_sum as f64/denom;
    let fwd_avg = fwd_sum as f64/denom;
    let rec_fwd_avg = rec_fwd_sum as f64/denom;
    let rep_avg = rep_sum as f64/denom;
    let total_auth_avg = total_auth_sum as f64/denom;
    let total_fwd_avg = total_fwd_sum as f64/denom;
    
    println!("------------------- TRACEBACK STATS -----------------------");
    println!("Authoring a message: {:}ms", auth_avg);
    println!("Forwarding a message: {:}ms", fwd_avg);
    println!();
    println!("Processing a message: {:}ms", proc_avg);
    println!();
    println!("Receiving an authored message: {:}ms", rec_avg);
    println!("Receiving a forwarded message: {:}ms", rec_fwd_avg);
    println!();
    println!("Reporting a message: {:}ms", rep_avg);
    println!();
    println!("Total time for an authored message: {:}ms", total_auth_avg);
    println!("Total time for a forwarded message: {:}ms", total_fwd_avg);
    println!();
}

fn time_no_trace(length: usize, iters: u64) {
    let mut rng = OsRng::new().unwrap();
    let (mut alice, mut bob) = User::new(&mut rng);
    let mut plaintext = vec![0; length]; 
        rng.fill_bytes(&mut plaintext);

    let mut send_sum_wo_trace = 0;
    let mut rec_sum_wo_trace = 0;
    let mut total_sum_wo_trace = 0;

    for _ in 1..iters {
        let mut start = Instant::now();
        let (h, ct) = alice.msg_scheme.ratchet_encrypt(&plaintext, AD, &mut rng);
        let duration_send = start.elapsed();
    
        start = Instant::now();
        bob.msg_scheme.ratchet_decrypt(&h, &ct, AD).unwrap();
        let duration_rec = start.elapsed();

        start = Instant::now();
        let (h, ct) = bob.msg_scheme.ratchet_encrypt(&plaintext, AD, &mut rng);
        alice.msg_scheme.ratchet_decrypt(&h, &ct, AD).unwrap();
        let duration_total = start.elapsed();

        send_sum_wo_trace = send_sum_wo_trace + duration_send.as_nanos();
        rec_sum_wo_trace = rec_sum_wo_trace + duration_rec.as_nanos();
        total_sum_wo_trace = total_sum_wo_trace + duration_total.as_nanos();
    }

    let avg_send = send_sum_wo_trace as f64/(iters as f64 * 1000000.0);
    let avg_rec = rec_sum_wo_trace as f64/(iters as f64 * 1000000.0);
    let avg_total = total_sum_wo_trace as f64/(iters as f64 * 1000000.0);

    println!("------------------- STATS WITHOUT TRACEBACK -----------------------");
    println!("Sending a message: {:}ms", avg_send);
    println!("Receiving a message: {:}ms", avg_rec);
    println!();
    println!("Total time: {:}ms", avg_total);
}

fn main() {
   println!("Testing on a short message (10 bytes)");
   println!();
   time_traceback(10, 1000);
   time_no_trace(10, 1000);

   println!();
   println!("Testing on a medium-short message (32 bytes)");
   println!();
   time_traceback(32, 1000);
   time_no_trace(32, 1000);

   println!();
   println!("Testing on a medium message (140 bytes)");
   println!();
   time_traceback(140, 1000);
   time_no_trace(140, 1000);

   println!();
   println!("Testing on a long message (300 bytes)");
   println!();
   time_traceback(300, 1000);
   time_no_trace(300, 1000);

   println!();
   println!("Testing on a very long message (500 bytes)");
   println!();
   time_traceback(500, 1000);
   time_no_trace(500, 1000);
    
}

