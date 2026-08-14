use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use netscan_core::scanner::target::{TargetResolver, TargetSpec};
use netscan_core::{PortSpec, Transport};

fn target_parsing(c: &mut Criterion) {
    let inputs = [
        ("address", "192.168.1.1"),
        ("cidr", "192.168.1.0/24"),
        ("range", "10.0.0.1-10.0.0.250"),
        ("hostname", "host.example.internal"),
        ("ipv6", "2001:db8::1"),
        ("ipv6-cidr", "2001:db8::/64"),
    ];

    let mut group = c.benchmark_group("target_parsing");
    for (name, input) in inputs {
        group.bench_with_input(BenchmarkId::from_parameter(name), input, |b, input| {
            b.iter(|| black_box(input.parse::<TargetSpec>().unwrap()));
        });
    }
    group.finish();
}

fn target_expansion(c: &mut Criterion) {
    let mut group = c.benchmark_group("target_expansion");
    for (name, spec, hosts) in [
        ("/24", "192.168.1.0/24", 254u64),
        ("/22", "192.168.0.0/22", 1022),
        ("/20", "192.168.0.0/20", 4094),
        ("/16", "10.0.0.0/16", 65534),
    ] {
        let specs = vec![spec.parse::<TargetSpec>().unwrap()];
        let resolver = TargetResolver::new().with_max_targets(100_000);
        group.throughput(Throughput::Elements(hosts));
        group.bench_function(BenchmarkId::from_parameter(name), |b| {
            b.iter(|| {
                let (targets, _) = resolver.expand_literals(black_box(&specs)).unwrap();
                black_box(targets.len())
            });
        });
    }
    group.finish();
}

fn exclusion_filtering(c: &mut Criterion) {
    let specs = vec!["10.0.0.0/16".parse::<TargetSpec>().unwrap()];
    let exclusions: Vec<TargetSpec> = (0..32)
        .map(|i| format!("10.0.{i}.0/24").parse::<TargetSpec>().unwrap())
        .collect();

    let mut group = c.benchmark_group("exclusions");
    group.throughput(Throughput::Elements(65_534));
    group.bench_function("none", |b| {
        let resolver = TargetResolver::new().with_max_targets(100_000);
        b.iter(|| black_box(resolver.expand_literals(&specs).unwrap().0.len()));
    });
    group.bench_function("32_blocks", |b| {
        let resolver = TargetResolver::new()
            .with_max_targets(100_000)
            .with_exclusions(exclusions.clone());
        b.iter(|| black_box(resolver.expand_literals(&specs).unwrap().0.len()));
    });
    group.finish();
}

fn port_parsing(c: &mut Criterion) {
    let inputs = [
        ("single", "80"),
        ("list", "22,80,443,3306,5432,8080,8443"),
        ("range", "1-1024"),
        ("full", "1-65535"),
        ("mixed", "22,80,443,1000-2000,8000-9000"),
        ("transports", "T:22,80,443,U:53,161,123"),
    ];

    let mut group = c.benchmark_group("port_parsing");
    for (name, input) in inputs {
        group.bench_with_input(BenchmarkId::from_parameter(name), input, |b, input| {
            b.iter(|| black_box(PortSpec::parse(input, Transport::Tcp).unwrap()));
        });
    }
    group.finish();
}

fn port_resolution(c: &mut Criterion) {
    let mut group = c.benchmark_group("port_resolution");
    for (name, input, ports) in [
        ("1024", "1-1024", 1024u64),
        ("full_range", "1-65535", 65535),
        ("both_transports", "T:1-30000,U:1-30000", 60000),
    ] {
        let spec = PortSpec::parse(input, Transport::Tcp).unwrap();
        group.throughput(Throughput::Elements(ports));
        group.bench_function(BenchmarkId::from_parameter(name), |b| {
            b.iter(|| black_box(spec.resolve().total()));
        });
    }
    group.finish();
}

fn top_ports(c: &mut Criterion) {
    c.bench_function("top_ports_1000", |b| {
        b.iter(|| black_box(netscan_core::detection::service::top_tcp_ports(1000).len()));
    });
    c.bench_function("service_name_lookup", |b| {
        b.iter(|| {
            for port in [22u16, 80, 443, 3306, 61234] {
                black_box(netscan_core::detection::service::name_for_port(
                    Transport::Tcp,
                    port,
                ));
            }
        });
    });
}

criterion_group!(
    benches,
    target_parsing,
    target_expansion,
    exclusion_filtering,
    port_parsing,
    port_resolution,
    top_ports
);
criterion_main!(benches);
