use double_ratchet_imp::scheme_1::*;
use double_ratchet_imp::d_ratchet::*;
use rand_os::OsRng;
use rand_core::RngCore;
use rand::rngs::OsRng as OtherRng;

use double_ratchet_imp::scheme_2::{Platform as S2Plat, User as S2User};

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, BatchSize};

fn scheme_1(c: &mut Criterion) {

    let sizes = [10, 100, 200, 500, 800, 1000, 2000, 5000, 8000];
    let plat = Platform::new();

    let mut group = c.benchmark_group("no source-tracking");
    for size in sizes.iter() {
        group.bench_with_input(BenchmarkId::new("send and receive", size), size, |b, &size| {
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

        group.bench_with_input(BenchmarkId::new("send only", size), size, |b, &size| {
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
                let (_h, _ct) = alice.msg_scheme.ratchet_encrypt(&plaintext1, AD, &mut rng);
            },
            BatchSize::SmallInput
        );
        });

        group.bench_with_input(BenchmarkId::new("receive only", size), size, |b, &size| {
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

    let mut group = c.benchmark_group("with source-tracking");
    for size in sizes.iter() {
        //author and receive
        group.bench_with_input(BenchmarkId::new("author and receive", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new_ed(&mut rng, plat.ed_sigkeys.public);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (comm, e) = alice.author_ed(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send_ed(&alice.userid, &comm);
                let (_, _fd) = bob.receive_ed((sig, src, e));
                (bob, alice, plaintext1, rng)
            }
            , 
            |(mut bob, mut alice, plaintext1, mut rng)| {
            let (comm, e) = bob.author_ed(&plaintext1, &mut rng);
            let (sig, src) = plat.process_send_ed(&bob.userid, &comm);
            alice.receive_ed((sig, src, e));
            },
            BatchSize::SmallInput
        );
        });

        //forward and receive
        group.bench_with_input(BenchmarkId::new("forward and receive", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new_ed(&mut rng, plat.ed_sigkeys.public);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (comm, e) = alice.author_ed(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send_ed(&alice.userid, &comm);
                let (_, fd) = bob.receive_ed((sig, src, e));
                (fd, bob, alice, plaintext1, rng)
            }
            , 
            |(fd, mut bob, mut alice, plaintext1, mut rng)| {
            let (comm, e) = bob.fwd(&plaintext1, fd, &mut rng);
            let (sig, src) = plat.process_send_ed(&bob.userid, &comm);
            alice.receive_ed((sig, src, e));
            },
            BatchSize::SmallInput
        );
        });

        //only author
        group.bench_with_input(BenchmarkId::new("only author", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new_ed(&mut rng, plat.ed_sigkeys.public);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (comm, e) = alice.author_ed(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send_ed(&alice.userid, &comm);
                let (_, _fd) = bob.receive_ed((sig, src, e));
                (bob, plaintext1, rng)
            }
            , 
            |(mut bob, plaintext1, mut rng)| {
            let (_comm, _e) = bob.author_ed(&plaintext1, &mut rng);
            },
            BatchSize::SmallInput
        );
        });

        //only forward
        group.bench_with_input(BenchmarkId::new("only forward", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new_ed(&mut rng, plat.ed_sigkeys.public);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (comm, e) = alice.author_ed(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send_ed(&alice.userid, &comm);
                let (_, fd) = bob.receive_ed((sig, src, e));
                (fd, bob, plaintext1, rng)
            }
            , 
            |(fd, mut bob, plaintext1, mut rng)| {
            let (_comm, _e) = bob.fwd(&plaintext1, fd, &mut rng);
            },
            BatchSize::SmallInput
        );
        });

        //only receive author
        group.bench_with_input(BenchmarkId::new("receive authored", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new_ed(&mut rng, plat.ed_sigkeys.public);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (comm, e) = alice.author_ed(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send_ed(&alice.userid, &comm);
                let (_, _fd) = bob.receive_ed((sig, src, e));
                let (comm, e) = bob.author_ed(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send_ed(&bob.userid, &comm);
                (alice, sig, src, e)
            }
            , 
            |(mut alice, sig, src, e)| {
            alice.receive_ed((sig, src, e));
            },
            BatchSize::SmallInput
        );
        });

        //only receive forward
        group.bench_with_input(BenchmarkId::new("receive forward", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new_ed(&mut rng, plat.ed_sigkeys.public);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (comm, e) = alice.author_ed(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send_ed(&alice.userid, &comm);
                let (_, fd) = bob.receive_ed((sig, src, e));
                let (comm, e) = bob.fwd(&plaintext1, fd, &mut rng);
                let (sig, src) = plat.process_send_ed(&bob.userid, &comm);
                (alice, sig, src, e)
            }
            , 
            |(mut alice, sig, src, e)| {
            alice.receive_ed((sig, src, e));
            },
            BatchSize::SmallInput
        );
        });
        
        //process send
        group.bench_with_input(BenchmarkId::new("process send", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new_ed(&mut rng, plat.ed_sigkeys.public);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (comm, e) = alice.author_ed(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send_ed(&alice.userid, &comm);
                let (_, _fd) = bob.receive_ed((sig, src, e));
                let (comm, _e) = bob.author_ed(&plaintext1, &mut rng);
                (bob, comm)
            }
            , 
            |(bob, comm)| {
                let (_sig, _src) = plat.process_send_ed(&bob.userid, &comm);
            },
            BatchSize::SmallInput
        );
        });

        //report
        group.bench_with_input(BenchmarkId::new("report", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng = OsRng::new().unwrap();
                let (mut alice, mut bob) = User::new_ed(&mut rng, plat.ed_sigkeys.public);
                let mut plaintext1 = vec![0; size];
                rng.fill_bytes(&mut plaintext1);
                let (comm, e) = alice.author_ed(&plaintext1, &mut rng);
                let (sig, src) = plat.process_send_ed(&alice.userid, &comm);
                let (_, fd) = bob.receive_ed((sig, src, e));
                let (_comm, _e) = bob.author_ed(&plaintext1, &mut rng);
                (plaintext1.to_vec(), fd.to_vec())
            }
            , 
            |(plaintext1, fd)| {
                plat.process_report_ed(plaintext1, fd);
            },
            BatchSize::SmallInput
        );
        });
    }
    group.finish();
}

fn scheme_2(c: &mut Criterion) {
    let sizes = [10, 100, 200, 500, 800, 1000, 2000, 5000, 8000];

    let mut group = c.benchmark_group("scheme 2");
    for size in sizes.iter() {
        group.bench_with_input(BenchmarkId::new("author and receive", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng1 = OsRng::new().unwrap();
                let mut plaintext1 = vec![0; size];
                rng1.fill_bytes(&mut plaintext1);


                let mut rng = OtherRng {};
                let plat = S2Plat::new(&mut rng);
                let (mut u1, mut u2) = S2User::new(&mut rng, &plat);
                let pd = u1.author(&mut rng, &plat, b"test");
                let (_msg, _fd) = u2.receive(pd, &plat, &mut rng);
                
                (u1, u2, plaintext1, rng, plat)
            }
            , 
            |(mut u1, mut u2, plaintext1, mut rng, plat)| {
                let pd = u2.author(&mut rng, &plat, &plaintext1);
                let (_msg, _fd) = u1.receive(pd, &plat, &mut rng);
            },
            BatchSize::SmallInput
        );
        });

        group.bench_with_input(BenchmarkId::new("forward and receive", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng1 = OsRng::new().unwrap();
                let mut plaintext1 = vec![0; size];
                rng1.fill_bytes(&mut plaintext1);


                let mut rng = OtherRng {};
                let plat = S2Plat::new(&mut rng);
                let (mut u1, mut u2) = S2User::new(&mut rng, &plat);
                let pd = u1.author(&mut rng, &plat, &plaintext1);
                let (_msg, fd) = u2.receive(pd, &plat, &mut rng);
                
                (u1, u2, plaintext1, rng, plat, fd)
            }
            , 
            |(mut u1, mut u2, plaintext1, mut rng, plat, fd)| {
                let pd = u2.forward(&mut rng, &plat, &plaintext1, fd);
                let (_msg, _fd) = u1.receive(pd, &plat, &mut rng);
            },
            BatchSize::SmallInput
        );
        });

        group.bench_with_input(BenchmarkId::new("only author", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng1 = OsRng::new().unwrap();
                let mut plaintext1 = vec![0; size];
                rng1.fill_bytes(&mut plaintext1);


                let mut rng = OtherRng {};
                let plat = S2Plat::new(&mut rng);
                let (mut u1, mut u2) = S2User::new(&mut rng, &plat);
                let pd = u1.author(&mut rng, &plat, b"test");
                let (_msg, _fd) = u2.receive(pd, &plat, &mut rng);
                
                (u2, plaintext1, rng, plat)
            }
            , 
            |(mut u2, plaintext1, mut rng, plat)| {
                let _pd = u2.author(&mut rng, &plat, &plaintext1);
            },
            BatchSize::SmallInput
        );
        });

        group.bench_with_input(BenchmarkId::new("only forward", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng1 = OsRng::new().unwrap();
                let mut plaintext1 = vec![0; size];
                rng1.fill_bytes(&mut plaintext1);


                let mut rng = OtherRng {};
                let plat = S2Plat::new(&mut rng);
                let (mut u1, mut u2) = S2User::new(&mut rng, &plat);
                let pd = u1.author(&mut rng, &plat, &plaintext1);
                let (_msg, fd) = u2.receive(pd, &plat, &mut rng);
                
                (u2, plaintext1, rng, plat, fd)
            }
            , 
            |(mut u2, plaintext1, mut rng, plat, fd)| {
                let _pd = u2.forward(&mut rng, &plat, &plaintext1, fd);
            },
            BatchSize::SmallInput
        );
        });

        group.bench_with_input(BenchmarkId::new("only receive (author)", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng1 = OsRng::new().unwrap();
                let mut plaintext1 = vec![0; size];
                rng1.fill_bytes(&mut plaintext1);


                let mut rng = OtherRng {};
                let plat = S2Plat::new(&mut rng);
                let (mut u1, mut u2) = S2User::new(&mut rng, &plat);
                let pd = u1.author(&mut rng, &plat, b"test");
                let (_msg, _fd) = u2.receive(pd, &plat, &mut rng);
                let pd = u2.author(&mut rng, &plat, &plaintext1);

                (u1, rng, plat, pd)
            }
            , 
            |(mut u1, mut rng, plat, pd)| {
                let (_msg, _fd) = u1.receive(pd, &plat, &mut rng);
            },
            BatchSize::SmallInput
        );
        });

        group.bench_with_input(BenchmarkId::new("only receive (forward)", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng1 = OsRng::new().unwrap();
                let mut plaintext1 = vec![0; size];
                rng1.fill_bytes(&mut plaintext1);


                let mut rng = OtherRng {};
                let plat = S2Plat::new(&mut rng);
                let (mut u1, mut u2) = S2User::new(&mut rng, &plat);
                let pd = u1.author(&mut rng, &plat, &plaintext1);
                let (_msg, fd) = u2.receive(pd, &plat, &mut rng);
                let pd = u2.forward(&mut rng, &plat, &plaintext1, fd);
                (u1, rng, plat, pd)
            }
            , 
            |(mut u1, mut rng, plat, pd)| {
                let (_msg, _fd) = u1.receive(pd, &plat, &mut rng);
            },
            BatchSize::SmallInput
        );
        });

        group.bench_with_input(BenchmarkId::new("report", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng1 = OsRng::new().unwrap();
                let mut plaintext1 = vec![0; size];
                rng1.fill_bytes(&mut plaintext1);


                let mut rng = OtherRng {};
                let plat = S2Plat::new(&mut rng);
                let (mut u1, mut u2) = S2User::new(&mut rng, &plat);
                let pd = u1.author(&mut rng, &plat, &plaintext1);
                let (_msg, fd) = u2.receive(pd, &plat, &mut rng);
                (u2, rng, plat, fd, plaintext1)
            }
            , 
            |(mut u2, mut rng, plat, fd, plaintext1)| {
                let rep = u2.report(fd, &mut rng, &plat);
                let _uid = plat.validate_report(&plaintext1, rep);
            },
            BatchSize::SmallInput
        );
        });

        group.bench_with_input(BenchmarkId::new("send, only user", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng1 = OsRng::new().unwrap();
                let mut plaintext1 = vec![0; size];
                rng1.fill_bytes(&mut plaintext1);


                let mut rng = OtherRng {};
                let plat = S2Plat::new(&mut rng);
                let (mut u1, mut u2) = S2User::new(&mut rng, &plat);
                let pd = u1.author(&mut rng, &plat, b"test");
                let (_msg, _fd) = u2.receive(pd, &plat, &mut rng);
                
                (u2, plaintext1, rng, plat)
            }
            , 
            |(mut u2, plaintext1, mut rng, plat)| {
                let _pd = u2.author_user_only(&mut rng, &plat, &plaintext1);
            },
            BatchSize::SmallInput
        );
        });

        group.bench_with_input(BenchmarkId::new("receive, only platform", size), size, |b, &size| {
            b.iter_batched(|| {
                //setup
                let mut rng1 = OsRng::new().unwrap();
                let mut plaintext1 = vec![0; size];
                rng1.fill_bytes(&mut plaintext1);


                let mut rng = OtherRng {};
                let plat = S2Plat::new(&mut rng);
                let (mut u1, mut u2) = S2User::new(&mut rng, &plat);
                let pd = u1.author(&mut rng, &plat, b"test");
                let out = u2.receive_send_only(pd, &plat, &mut rng);

                let pk = out.1.decompress().unwrap();
                let attr = ((out.2.0.0.decompress().unwrap(), out.2.0.1.decompress().unwrap()), 
                (out.2.1.0.decompress().unwrap(), out.2.1.1.decompress().unwrap()), 
                (out.2.2.0.decompress().unwrap(), out.2.2.1.decompress().unwrap()));
                
                (rng, plat, out, pk, attr)
            }
            , 
            |(mut rng, plat, out, pk, attr)| {
                plat.verify_receive(out.0, out.1, 
                    out.2, 
                    out.3, out.4, out.5, 
                    out.6, out.7);
        
                let _cert = plat.issue_cert(&mut rng, pk, 
                attr);
        
            },
            BatchSize::SmallInput
        );
        });
    }
    group.finish();
}

criterion_group!(benches, scheme_1, scheme_2);
criterion_main!(benches);