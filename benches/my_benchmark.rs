use double_ratchet_imp::traceback::*;
use double_ratchet_imp::d_ratchet::*;
use rand_os::OsRng;
use rand_core::RngCore;

use criterion::{black_box, criterion_group, criterion_main, Criterion};


fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = OsRng::new().unwrap();
    let plat = Platform::new();
    let (mut alice, mut bob) = User::new(&mut rng);
    let mut plaintext = vec![0; 5000];
    rng.fill_bytes(&mut plaintext);

    //c.bench_function("author", |b| b.iter(|| alice.author(&plaintext, &mut rng)));
    c.bench_function("total trace author and fwd long", |b| b.iter(|| {
        let (comm, e) = alice.author(&plaintext, &mut rng);
        let (sig, src) = plat.process_send(&alice.userid, &comm);
        let (_, fd) = bob.receive((sig, src, e), &plat);
        let (comm, e) = bob.fwd(&plaintext, fd, &mut rng);
        let (sig, src) = plat.process_send(&bob.userid, &comm);
        alice.receive((sig, src, e), &plat);
    }));

    c.bench_function("total no trace exchange long", |b| b.iter(|| {
        let (h, ct) = bob.msg_scheme.ratchet_encrypt(&plaintext, AD, &mut rng);
        alice.msg_scheme.ratchet_decrypt(&h, &ct, AD).unwrap();
        let (h, ct) = alice.msg_scheme.ratchet_encrypt(&plaintext, AD, &mut rng);
        bob.msg_scheme.ratchet_decrypt(&h, &ct, AD).unwrap();
    }));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);