//! Protocol Layer Benchmarks
//!
//! Measures message construction, serialization, parsing, and throughput.
//!
//! Run: cargo bench --bench protocol_bench

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use walkie_talkie_core::identity::IdentityBuilder;
use walkie_talkie_core::protocol::{AgentMessage, MessageId};

fn make_identity(name: &str) -> walkie_talkie_core::identity::AgentIdentity {
    IdentityBuilder::new(name).build().expect("identity build failed").0
}

fn bench_message_construction(c: &mut Criterion) {
    let alice = make_identity("Alice 🤖");
    let bob = make_identity("Bob 🔧");

    let mut group = c.benchmark_group("protocol/construction");

    group.bench_function("text_message", |b| {
        b.iter(|| {
            black_box(AgentMessage::text(&alice, "Hello, this is a test message payload!"))
        })
    });

    group.bench_function("intent_message", |b| {
        b.iter(|| {
            black_box(AgentMessage::intent(&alice, &bob, "code-review", "Review PR #42"))
        })
    });

    group.bench_function("task_message", |b| {
        b.iter(|| {
            black_box(AgentMessage::task(
                &alice,
                &bob,
                "run-benchmark",
                serde_json::json!({"target": "crypto", "iterations": 1000}),
            ))
        })
    });

    group.finish();
}

fn bench_message_serialization(c: &mut Criterion) {
    let alice = make_identity("Alice 🤖");
    let msg = AgentMessage::task(
        &alice,
        &make_identity("Bob 🔧"),
        "benchmark",
        serde_json::json!({"key": "value", "nested": {"data": [1, 2, 3]}}),
    );
    let serialized = msg.to_json_bytes().unwrap();

    let mut group = c.benchmark_group("protocol/serialization");
    group.throughput(Throughput::Bytes(serialized.len() as u64));

    group.bench_function("serialize_to_json", |b| {
        b.iter(|| black_box(msg.to_json_bytes().unwrap()))
    });

    group.bench_function("deserialize_from_json", |b| {
        b.iter(|| black_box(AgentMessage::from_json_bytes(&serialized).unwrap()))
    });

    group.bench_function("full_roundtrip", |b| {
        b.iter(|| {
            let bytes = msg.to_json_bytes().unwrap();
            black_box(AgentMessage::from_json_bytes(&bytes).unwrap())
        })
    });

    group.finish();
}

fn bench_message_id_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol/message_id");
    group.throughput(Throughput::Elements(1));

    group.bench_function("generate", |b| {
        b.iter(|| black_box(MessageId::generate("agent-001")))
    });

    group.finish();
}

fn bench_reply_chain(c: &mut Criterion) {
    let alice = make_identity("Alice 🤖");

    let mut group = c.benchmark_group("protocol/reply_chain");
    group.bench_function("reply_depth_10", |b| {
        b.iter_with_setup(
            || AgentMessage::text(&alice, "Original message"),
            |mut msg| {
                for i in 0..10 {
                    msg = msg.make_reply(serde_json::json!({"reply": i}));
                    black_box(&msg);
                }
            },
        )
    });
    group.finish();
}

fn bench_high_throughput_messages(c: &mut Criterion) {
    let alice = make_identity("Alice 🤖");
    let mut group = c.benchmark_group("protocol/high_throughput");
    group.throughput(Throughput::Elements(10_000));
    group.sample_size(50);

    group.bench_function("10k_messages_roundtrip", |b| {
        let template = AgentMessage::text(&alice, "Benchmark payload data");
        b.iter(|| {
            for _ in 0..10_000 {
                let bytes = black_box(template.to_json_bytes().unwrap());
                black_box(AgentMessage::from_json_bytes(&bytes).unwrap());
            }
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_message_construction,
    bench_message_serialization,
    bench_message_id_generation,
    bench_reply_chain,
    bench_high_throughput_messages,
);
criterion_main!(benches);
