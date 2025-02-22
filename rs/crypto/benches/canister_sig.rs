use criterion::*;
use ic_crypto_test_utils_canister_sigs::new_valid_sig_and_crypto_component;
use ic_interfaces::crypto::CanisterSigVerifier;
use ic_types::RegistryVersion;

criterion_group!(benches, crypto_canister_sig_verify);
criterion_main!(benches);

fn crypto_canister_sig_verify(criterion: &mut Criterion) {
    for group_suffix in ["cached", "uncached"] {
        crypto_canister_sig_verify_impl(criterion, group_suffix);
    }
}

fn crypto_canister_sig_verify_impl(criterion: &mut Criterion, group_suffix: &str) {
    let group = &mut criterion.benchmark_group(format!("crypto_canister_sig_{group_suffix}"));

    for benchmark_name in ["with_delegations", "without_delegations"] {
        group.bench_function(benchmark_name, |bench| {
            bench.iter_batched_ref(
                || {
                    let data = new_valid_sig_and_crypto_component(
                        &mut rand::thread_rng(),
                        REG_V1,
                        benchmark_name == "with_delegations",
                    );
                    if group_suffix == "cached" {
                        // cache the signature verification before benchmarking
                        let result = data.crypto.verify_canister_sig(
                            &data.canister_sig,
                            &data.msg,
                            &data.canister_pk,
                            REG_V1,
                        );
                        assert!(result.is_ok());
                    }
                    data
                },
                |data| {
                    let result = data.crypto.verify_canister_sig(
                        &data.canister_sig,
                        &data.msg,
                        &data.canister_pk,
                        REG_V1,
                    );
                    assert!(result.is_ok());
                },
                BatchSize::SmallInput,
            )
        });
    }
}

const REG_V1: RegistryVersion = RegistryVersion::new(5);
