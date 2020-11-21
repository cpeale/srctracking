/*use criterion::{black_box, criterion_group, criterion_main, Criterion};


fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = OsRng::new().unwrap();
    let plat = Platform::new();
    let (mut alice, mut bob) = User::new(&mut rng);
    let mut plaintext = vec![0; 40];
    rng.fill_bytes(&mut plaintext);

    c.bench_function("author", |b| b.iter(|| alice.author(&plaintext, &mut rng)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);*/