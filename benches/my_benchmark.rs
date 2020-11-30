use double_ratchet_imp::traceback::*;
use double_ratchet_imp::d_ratchet::*;
use rand_os::OsRng;
use rand_core::RngCore;

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, BatchSize};


fn criterion_benchmark(c: &mut Criterion) {

    let sizes = [10, 100, 200, 500, 800, 1000, 2000, 5000, 8000];
    let plat = Platform::new();

    let mut group = c.benchmark_group("send and receive");
    for size in sizes.iter() {
        group.bench_with_input(BenchmarkId::new("author with traceback", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new(&mut rng);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (comm, e) = alice.author(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send(&alice.userid, &comm);
                let (_, fd) = bob.receive((sig, src, e), &plat);
                (bob, alice, plaintext1, rng)
            }
            , 
            |(mut bob, mut alice, plaintext1, mut rng)| {
            let (comm, e) = bob.author(&plaintext1, &mut rng);
            let (sig, src) = plat.process_send(&bob.userid, &comm);
            alice.receive((sig, src, e), &plat);
            },
            BatchSize::SmallInput
        );
        });

        group.bench_with_input(BenchmarkId::new("forward with traceback", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new(&mut rng);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (comm, e) = alice.author(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send(&alice.userid, &comm);
                let (_, fd) = bob.receive((sig, src, e), &plat);
                (fd, bob, alice, plaintext1, rng)
            }
            , 
            |(fd, mut bob, mut alice, plaintext1, mut rng)| {
            let (comm, e) = bob.fwd(&plaintext1, fd, &mut rng);
            let (sig, src) = plat.process_send(&bob.userid, &comm);
            alice.receive((sig, src, e), &plat);
            },
            BatchSize::SmallInput
        );
        });

        group.bench_with_input(BenchmarkId::new("no traceback", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new(&mut rng);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (h, ct) = bob.msg_scheme.ratchet_encrypt(&plaintext1, AD, &mut rng);
                alice.msg_scheme.ratchet_decrypt(&h, &ct, AD).unwrap();
                (bob, alice, plaintext1, rng)
            }
            , 
            |(mut bob, mut alice, plaintext1, mut rng)| {
                let (h, ct) = alice.msg_scheme.ratchet_encrypt(&plaintext1, AD, &mut rng);
                bob.msg_scheme.ratchet_decrypt(&h, &ct, AD).unwrap();
            },
            BatchSize::SmallInput
        );
        });
    }
    group.finish();

    let mut group = c.benchmark_group("send only");
    for size in sizes.iter() {
        //group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("author with traceback", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new(&mut rng);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (comm, e) = alice.author(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send(&alice.userid, &comm);
                let (_, fd) = bob.receive((sig, src, e), &plat);
                (bob, plaintext1, rng)
            }
            , 
            |(mut bob, plaintext1, mut rng)| {
            let (comm, e) = bob.author(&plaintext1, &mut rng);
            },
            BatchSize::SmallInput
        );
        });

        group.bench_with_input(BenchmarkId::new("forward with traceback", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new(&mut rng);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (comm, e) = alice.author(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send(&alice.userid, &comm);
                let (_, fd) = bob.receive((sig, src, e), &plat);
                (fd, bob, plaintext1, rng)
            }
            , 
            |(fd, mut bob, plaintext1, mut rng)| {
            let (comm, e) = bob.fwd(&plaintext1, fd, &mut rng);
            },
            BatchSize::SmallInput
        );
        });

        group.bench_with_input(BenchmarkId::new("no traceback", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new(&mut rng);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (h, ct) = bob.msg_scheme.ratchet_encrypt(&plaintext1, AD, &mut rng);
                alice.msg_scheme.ratchet_decrypt(&h, &ct, AD).unwrap();
                (alice, plaintext1, rng)
            }
            , 
            |(mut alice, plaintext1, mut rng)| {
                let (h, ct) = alice.msg_scheme.ratchet_encrypt(&plaintext1, AD, &mut rng);
            },
            BatchSize::SmallInput
        );
        });
    }
    group.finish();

    let mut group = c.benchmark_group("receive only");
    for size in sizes.iter() {
        group.bench_with_input(BenchmarkId::new("author with traceback", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new(&mut rng);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (comm, e) = alice.author(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send(&alice.userid, &comm);
                let (_, fd) = bob.receive((sig, src, e), &plat);
                let (comm, e) = bob.author(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send(&bob.userid, &comm);
                (alice, sig, src, e)
            }
            , 
            |(mut alice, sig, src, e)| {
            alice.receive((sig, src, e), &plat);
            },
            BatchSize::SmallInput
        );
        });

        group.bench_with_input(BenchmarkId::new("forward with traceback", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new(&mut rng);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (comm, e) = alice.author(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send(&alice.userid, &comm);
                let (_, fd) = bob.receive((sig, src, e), &plat);
                let (comm, e) = bob.fwd(&plaintext1, fd, &mut rng);
                let (sig, src) = plat.process_send(&bob.userid, &comm);
                (alice, sig, src, e)
            }
            , 
            |(mut alice, sig, src, e)| {
            alice.receive((sig, src, e), &plat);
            },
            BatchSize::SmallInput
        );
        });

        group.bench_with_input(BenchmarkId::new("no traceback", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new(&mut rng);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (h, ct) = bob.msg_scheme.ratchet_encrypt(&plaintext1, AD, &mut rng);
                alice.msg_scheme.ratchet_decrypt(&h, &ct, AD).unwrap();
                let (h, ct) = alice.msg_scheme.ratchet_encrypt(&plaintext1, AD, &mut rng);
                (bob, h, ct)
            }
            , 
            |(mut bob, h, ct)| {
                bob.msg_scheme.ratchet_decrypt(&h, &ct, AD).unwrap();
            },
            BatchSize::SmallInput
        );
        });
    }
    group.finish();

    let mut group = c.benchmark_group("process message (traceback)");
    for size in sizes.iter() {
        group.bench_with_input(BenchmarkId::new("with md", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new(&mut rng);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (comm, e) = alice.author(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send(&alice.userid, &comm);
                let (_, fd) = bob.receive((sig, src, e), &plat);
                let (comm, e) = bob.author(&plaintext1, &mut rng);
                (bob, comm)
            }
            , 
            |(bob, comm)| {
                let (sig, src) = plat.process_send(&bob.userid, &comm);
            },
            BatchSize::SmallInput
        );
        });

        group.bench_with_input(BenchmarkId::new("no md", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new(&mut rng);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (comm, e) = alice.author(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send(&alice.userid, &comm);
                let (_, fd) = bob.receive((sig, src, e), &plat);
                let (comm, e) = bob.author(&plaintext1, &mut rng);
                (bob, comm)
            }
            , 
            |(bob, comm)| {
                let (sig, src) = plat.process_send_wo_md(&bob.userid, &comm);
            },
            BatchSize::SmallInput
        );
        });

        group.bench_with_input(BenchmarkId::new("no src", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new(&mut rng);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (comm, e) = alice.author(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send(&alice.userid, &comm);
                let (_, fd) = bob.receive((sig, src, e), &plat);
                let (comm, e) = bob.author(&plaintext1, &mut rng);
                (bob, comm)
            }
            , 
            |(bob, comm)| {
                let (sig, src) = plat.process_send_wo_tag(&bob.userid, &comm);
            },
            BatchSize::SmallInput
        );
        });

        group.bench_with_input(BenchmarkId::new("no sig", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new(&mut rng);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (comm, e) = alice.author(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send(&alice.userid, &comm);
                let (_, fd) = bob.receive((sig, src, e), &plat);
                let (comm, e) = bob.author(&plaintext1, &mut rng);
                (bob, comm)
            }
            , 
            |(bob, comm)| {
                let (sig, src) = plat.process_send_wo_sig(&bob.userid, &comm);
            },
            BatchSize::SmallInput
        );
        });

        group.bench_with_input(BenchmarkId::new("sig with sha 512", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new(&mut rng);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (comm, e) = alice.author(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send(&alice.userid, &comm);
                let (_, fd) = bob.receive((sig, src, e), &plat);
                let (comm, e) = bob.author(&plaintext1, &mut rng);
                (bob, comm)
            }
            , 
            |(bob, comm)| {
                let (sig, src) = plat.process_send_sha_512(&bob.userid, &comm);
            },
            BatchSize::SmallInput
        );
        });

        group.bench_with_input(BenchmarkId::new("sig with sha 384", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new(&mut rng);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (comm, e) = alice.author(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send(&alice.userid, &comm);
                let (_, fd) = bob.receive((sig, src, e), &plat);
                let (comm, e) = bob.author(&plaintext1, &mut rng);
                (bob, comm)
            }
            , 
            |(bob, comm)| {
                let (sig, src) = plat.process_send_sha_384(&bob.userid, &comm);
            },
            BatchSize::SmallInput
        );
        });
    }
    group.finish();

    let mut group = c.benchmark_group("report message (traceback)");
    for size in sizes.iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new(&mut rng);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (comm, e) = alice.author(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send(&alice.userid, &comm);
                let (_, fd) = bob.receive((sig, src, e), &plat);
                let (comm, e) = bob.author(&plaintext1, &mut rng);
                (plaintext1.to_vec(), fd.to_vec())
            }
            , 
            |(plaintext1, fd)| {
                plat.process_report(plaintext1, fd);
            },
            BatchSize::SmallInput
        );
        });
    }
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);