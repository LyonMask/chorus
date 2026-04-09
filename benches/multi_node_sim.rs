//! Multi-Node Simulation Benchmarks
//!
//! Simulates multi-tenant workloads using synchronous registry/ratelimiter APIs.
//! Measures registration, discovery, rate limiting, and cross-tenant isolation.
//!
//! Run: cargo bench --bench multi_node_sim

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use ed25519_dalek::SigningKey;
use walkie_talkie_core::identity::IdentityBuilder;
use walkie_talkie_core::ratelimit::RateLimiter;
use walkie_talkie_core::registry::AgentRegistry;

// ── Helpers ──────────────────────────────────────────────────────

fn make_agent(name: &str, caps: &[&str]) -> walkie_talkie_core::identity::AgentIdentity {
    let seed = {
        let mut b = name.as_bytes().to_vec();
        b.resize(32, 0);
        b
    };
    let sk = SigningKey::from_bytes(&seed.try_into().unwrap());
    IdentityBuilder::new(name)
        .capabilities(caps)
        .build_with_key(&sk)
        .expect("agent build failed")
}

// ── Registry benchmarks ──────────────────────────────────────────

fn bench_registry_register(c: &mut Criterion) {
    let mut group = c.benchmark_group("registry/register");

    for n_agents in [10u64, 100, 1000] {
        group.throughput(Throughput::Elements(n_agents));
        group.bench_with_input(
            BenchmarkId::new("batch_register", n_agents),
            &n_agents,
            |b, &n| {
                b.iter_with_setup(
                    || {
                        let reg = AgentRegistry::new();
                        reg.create_tenant("bench-tenant", "Benchmark").unwrap();
                        reg
                    },
                    |reg| {
                        for i in 0..n {
                            let agent = make_agent(&format!("Agent-{i}"), &["test"]);
                            black_box(reg.register_agent("bench-tenant", agent));
                        }
                    },
                )
            },
        );
    }
    group.finish();
}

fn bench_registry_discovery(c: &mut Criterion) {
    let mut group = c.benchmark_group("registry/discovery");

    for n_agents in [10u64, 100, 1000] {
        group.throughput(Throughput::Elements(n_agents));
        group.bench_with_input(
            BenchmarkId::new("find_agent", n_agents),
            &n_agents,
            |b, &n| {
                let reg = AgentRegistry::new();
                reg.create_tenant("bench-tenant", "Benchmark").unwrap();
                for i in 0..n {
                    let agent = make_agent(&format!("Agent-{i}"), &["common-cap"]);
                    reg.register_agent("bench-tenant", agent).unwrap();
                }

                b.iter(|| {
                    for i in 0..n {
                        black_box(reg.find_agent("bench-tenant", &format!("did:walkie:{i}")));
                    }
                })
            },
        );
    }
    group.finish();
}

fn bench_registry_list(c: &mut Criterion) {
    let mut group = c.benchmark_group("registry/list");

    for n_agents in [10u64, 100, 500] {
        group.throughput(Throughput::Elements(n_agents));
        group.bench_with_input(
            BenchmarkId::new("list_agents", n_agents),
            &n_agents,
            |b, &n| {
                let reg = AgentRegistry::new();
                reg.create_tenant("bench-tenant", "Benchmark").unwrap();
                for i in 0..n {
                    let agent = make_agent(&format!("Agent-{i}"), &["cap"]);
                    reg.register_agent("bench-tenant", agent).unwrap();
                }

                b.iter(|| black_box(reg.list_agents("bench-tenant").unwrap()));
            },
        );
    }
    group.finish();
}

// ── Rate Limiter benchmarks ──────────────────────────────────────

fn bench_rate_limiter_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratelimiter/throughput");

    for n_requests in [100u64, 1000, 10_000] {
        group.throughput(Throughput::Elements(n_requests));
        group.bench_with_input(
            BenchmarkId::new("try_acquire", n_requests),
            &n_requests,
            |b, &n| {
                b.iter(|| {
                    let limiter = RateLimiter::new(100, 10);
                    let mut allowed = 0u64;
                    for i in 0..n {
                        if limiter.try_acquire("tenant-a", &format!("agent-{i}"), 1) {
                            allowed += 1;
                        }
                    }
                    black_box(allowed);
                })
            },
        );
    }
    group.finish();
}

fn bench_rate_limiter_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratelimiter/contention");

    for burst in [50u32, 200, 1000] {
        group.bench_with_input(
            BenchmarkId::new("single_key_exhaust", burst),
            &burst,
            |b, &burst| {
                b.iter(|| {
                    let limiter = RateLimiter::new(burst, burst);
                    let mut allowed = 0u64;
                    // Send 2x burst requests — first burst allowed, rest rejected
                    for _ in 0..(burst as u64 * 2) {
                        if limiter.try_acquire("tenant-1", "agent-1", 1) {
                            allowed += 1;
                        }
                    }
                    black_box(allowed);
                })
            },
        );
    }
    group.finish();
}

// ── Multi-tenant isolation benchmark ─────────────────────────────

fn bench_multi_tenant_register(c: &mut Criterion) {
    let mut group = c.benchmark_group("registry/multi_tenant");

    for n_tenants in [5u64, 10, 20] {
        let agents_per = 50u64;
        let total = n_tenants * agents_per;
        group.throughput(Throughput::Elements(total));
        group.bench_with_input(
            BenchmarkId::new("cross_tenant_register", n_tenants),
            &n_tenants,
            |b, &n_t| {
                b.iter_with_setup(
                    || {
                        let reg = AgentRegistry::new();
                        for i in 0..n_t {
                            reg.create_tenant(&format!("tenant-{i}"), &format!("Tenant {i}"))
                                .unwrap();
                        }
                        reg
                    },
                    |reg| {
                        for ti in 0..n_t {
                            for j in 0..agents_per {
                                let agent =
                                    make_agent(&format!("Agent-{ti}-{j}"), &["common"]);
                                black_box(
                                    reg.register_agent(&format!("tenant-{ti}"), agent),
                                );
                            }
                        }
                    },
                )
            },
        );
    }
    group.finish();
}

fn bench_multi_tenant_rate_limit(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratelimiter/multi_tenant");

    for n_tenants in [10u64, 50, 100] {
        group.throughput(Throughput::Elements(n_tenants));
        group.bench_with_input(
            BenchmarkId::new("tenant_isolation", n_tenants),
            &n_tenants,
            |b, &n_t| {
                b.iter(|| {
                    let limiter = RateLimiter::new(100, 10);
                    let mut total_allowed = 0u64;
                    // Each tenant gets its own bucket
                    for i in 0..n_t {
                        for j in 0..10u64 {
                            if limiter
                                .try_acquire(
                                    &format!("tenant-{i}"),
                                    &format!("agent-{j}"),
                                    1,
                                )
                            {
                                total_allowed += 1;
                            }
                        }
                    }
                    black_box(total_allowed);
                })
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_registry_register,
    bench_registry_discovery,
    bench_registry_list,
    bench_rate_limiter_throughput,
    bench_rate_limiter_contention,
    bench_multi_tenant_register,
    bench_multi_tenant_rate_limit,
);
criterion_main!(benches);
