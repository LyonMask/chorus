//! Crypto Layer Performance Benchmarks
//!
//! Measures: key generation, DH exchange, session creation, encrypt/decrypt throughput.
//!
//! Run: cargo bench --bench crypto_bench

use chorus_core::crypto::{CryptoLayer, KeyPair};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn make_keypair() -> KeyPair {
    let crypto = CryptoLayer::new();
    crypto.generate_keypair().expect("keypair gen failed")
}

fn make_session(crypto: &mut CryptoLayer) {
    let alice = make_keypair();
    let bob = make_keypair();
    let shared = CryptoLayer::diffie_hellman(&alice.private, &bob.public).expect("dh failed");
    crypto.create_session("bench-peer", &shared);
}

fn bench_keypair_generation(c: &mut Criterion) {
    c.bench_function("crypto/keypair_generate", |b| {
        let crypto = CryptoLayer::new();
        b.iter(|| black_box(crypto.generate_keypair().unwrap()))
    });
}

fn bench_diffie_hellman(c: &mut Criterion) {
    c.bench_function("crypto/dh_exchange", |b| {
        let alice = make_keypair();
        let bob = make_keypair();
        b.iter(|| black_box(CryptoLayer::diffie_hellman(&alice.private, &bob.public).unwrap()))
    });
}

fn bench_session_creation(c: &mut Criterion) {
    c.bench_function("crypto/session_create", |b| {
        b.iter_with_setup(
            || {
                let alice = make_keypair();
                let bob = make_keypair();
                let shared = CryptoLayer::diffie_hellman(&alice.private, &bob.public).unwrap();
                (CryptoLayer::new(), shared)
            },
            |(mut crypto, shared)| {
                black_box(crypto.create_session("bench-peer", &shared));
            },
        )
    });
}

fn bench_encrypt_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto/encrypt_decrypt");

    for size in [64usize, 256, 1024, 4096, 16384] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("encrypt", size), &size, |b, &size| {
            let mut crypto = CryptoLayer::new();
            make_session(&mut crypto);
            let plaintext = vec![0xAB; size];
            b.iter(|| black_box(crypto.encrypt_for("bench-peer", &plaintext).unwrap()))
        });

        group.bench_with_input(BenchmarkId::new("decrypt", size), &size, |b, &size| {
            let mut crypto = CryptoLayer::new();
            make_session(&mut crypto);
            let plaintext = vec![0xAB; size];
            let ciphertext = crypto.encrypt_for("bench-peer", &plaintext).unwrap();
            b.iter(|| black_box(crypto.decrypt_from("bench-peer", &ciphertext).unwrap()))
        });
    }
    group.finish();
}

fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto/throughput");
    group.throughput(Throughput::Elements(1000));
    group.bench_function("1000_msgs_256b_roundtrip", |b| {
        b.iter_with_setup(
            || {
                let mut crypto = CryptoLayer::new();
                make_session(&mut crypto);
                let plaintext = vec![0x42; 256];
                (crypto, plaintext)
            },
            |(mut crypto, plaintext)| {
                for _ in 0..1000 {
                    let ct = crypto.encrypt_for("bench-peer", &plaintext).unwrap();
                    black_box(crypto.decrypt_from("bench-peer", &ct).unwrap());
                }
            },
        )
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_keypair_generation,
    bench_diffie_hellman,
    bench_session_creation,
    bench_encrypt_decrypt,
    bench_throughput,
);
criterion_main!(benches);
