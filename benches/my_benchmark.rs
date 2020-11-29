use double_ratchet_imp::traceback::*;
use double_ratchet_imp::d_ratchet::*;
use rand_os::OsRng;
use rand_core::RngCore;

use criterion::{black_box, criterion_group, criterion_main, Criterion};


fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = OsRng::new().unwrap();
    let plat = Platform::new();
    let (mut alice, mut bob) = User::new(&mut rng);
    let mut plaintext1 = vec![0; 10];
    let mut plaintext2 = vec![0; 100];
    let mut plaintext3 = vec![0; 500];
    let mut plaintext4 = vec![0; 1000];
    let mut plaintext5 = vec![0; 5000];
    //println!("{:?}", plaintext);
    rng.fill_bytes(&mut plaintext1);
    rng.fill_bytes(&mut plaintext2);
    rng.fill_bytes(&mut plaintext3);
    rng.fill_bytes(&mut plaintext4);
    rng.fill_bytes(&mut plaintext5);

    //c.bench_function("author", |b| b.iter(|| alice.author(&plaintext, &mut rng)));
    c.bench_function("total trace author and fwd 10", |b| b.iter(|| {
        let (comm, e) = alice.author(&plaintext1, &mut rng);
        let (sig, src) = plat.process_send(&alice.userid, &comm);
        let (_, fd) = bob.receive((sig, src, e), &plat);
        let (comm, e) = bob.fwd(&plaintext1, fd, &mut rng);
        let (sig, src) = plat.process_send(&bob.userid, &comm);
        alice.receive((sig, src, e), &plat);
    }));

    c.bench_function("total no trace exchange 10", |b| b.iter(|| {
        let (h, ct) = bob.msg_scheme.ratchet_encrypt(&plaintext1, AD, &mut rng);
        alice.msg_scheme.ratchet_decrypt(&h, &ct, AD).unwrap();
        let (h, ct) = alice.msg_scheme.ratchet_encrypt(&plaintext1, AD, &mut rng);
        bob.msg_scheme.ratchet_decrypt(&h, &ct, AD).unwrap();
    }));

    c.bench_function("total trace author and fwd 100", |b| b.iter(|| {
        let (comm, e) = alice.author(&plaintext2, &mut rng);
        let (sig, src) = plat.process_send(&alice.userid, &comm);
        let (_, fd) = bob.receive((sig, src, e), &plat);
        let (comm, e) = bob.fwd(&plaintext2, fd, &mut rng);
        let (sig, src) = plat.process_send(&bob.userid, &comm);
        alice.receive((sig, src, e), &plat);
    }));

    c.bench_function("total no trace exchange 100", |b| b.iter(|| {
        let (h, ct) = bob.msg_scheme.ratchet_encrypt(&plaintext2, AD, &mut rng);
        alice.msg_scheme.ratchet_decrypt(&h, &ct, AD).unwrap();
        let (h, ct) = alice.msg_scheme.ratchet_encrypt(&plaintext2, AD, &mut rng);
        bob.msg_scheme.ratchet_decrypt(&h, &ct, AD).unwrap();
    }));

    c.bench_function("total trace author and fwd 500", |b| b.iter(|| {
        let (comm, e) = alice.author(&plaintext3, &mut rng);
        let (sig, src) = plat.process_send(&alice.userid, &comm);
        let (_, fd) = bob.receive((sig, src, e), &plat);
        let (comm, e) = bob.fwd(&plaintext3, fd, &mut rng);
        let (sig, src) = plat.process_send(&bob.userid, &comm);
        alice.receive((sig, src, e), &plat);
    }));

    c.bench_function("total no trace exchange 500", |b| b.iter(|| {
        let (h, ct) = bob.msg_scheme.ratchet_encrypt(&plaintext3, AD, &mut rng);
        alice.msg_scheme.ratchet_decrypt(&h, &ct, AD).unwrap();
        let (h, ct) = alice.msg_scheme.ratchet_encrypt(&plaintext3, AD, &mut rng);
        bob.msg_scheme.ratchet_decrypt(&h, &ct, AD).unwrap();
    }));

    c.bench_function("total trace author and fwd 1000", |b| b.iter(|| {
        let (comm, e) = alice.author(&plaintext4, &mut rng);
        let (sig, src) = plat.process_send(&alice.userid, &comm);
        let (_, fd) = bob.receive((sig, src, e), &plat);
        let (comm, e) = bob.fwd(&plaintext4, fd, &mut rng);
        let (sig, src) = plat.process_send(&bob.userid, &comm);
        alice.receive((sig, src, e), &plat);
    }));

    c.bench_function("total no trace exchange 1000", |b| b.iter(|| {
        let (h, ct) = bob.msg_scheme.ratchet_encrypt(&plaintext4, AD, &mut rng);
        alice.msg_scheme.ratchet_decrypt(&h, &ct, AD).unwrap();
        let (h, ct) = alice.msg_scheme.ratchet_encrypt(&plaintext4, AD, &mut rng);
        bob.msg_scheme.ratchet_decrypt(&h, &ct, AD).unwrap();
    }));

    c.bench_function("total trace author and fwd 5000", |b| b.iter(|| {
        let (comm, e) = alice.author(&plaintext5, &mut rng);
        let (sig, src) = plat.process_send(&alice.userid, &comm);
        let (_, fd) = bob.receive((sig, src, e), &plat);
        let (comm, e) = bob.fwd(&plaintext5, fd, &mut rng);
        let (sig, src) = plat.process_send(&bob.userid, &comm);
        alice.receive((sig, src, e), &plat);
    }));

    c.bench_function("total no trace exchange 5000", |b| b.iter(|| {
        let (h, ct) = bob.msg_scheme.ratchet_encrypt(&plaintext5, AD, &mut rng);
        alice.msg_scheme.ratchet_decrypt(&h, &ct, AD).unwrap();
        let (h, ct) = alice.msg_scheme.ratchet_encrypt(&plaintext5, AD, &mut rng);
        bob.msg_scheme.ratchet_decrypt(&h, &ct, AD).unwrap();
    }));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);