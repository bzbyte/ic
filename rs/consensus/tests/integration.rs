mod framework;
use crate::framework::{
    malicious, setup_subnet, ConsensusDependencies, ConsensusInstance, ConsensusModifier,
    ConsensusRunner, ConsensusRunnerConfig,
};
use ic_consensus_utils::{membership::Membership, pool_reader::PoolReader};
use ic_interfaces::consensus_pool::ConsensusPool;
use ic_interfaces_registry::RegistryClient;
use ic_test_utilities::{
    types::ids::{node_test_id, subnet_test_id},
    FastForwardTimeSource,
};
use ic_types::{crypto::CryptoHash, replica_config::ReplicaConfig, Height};
use rand::Rng;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

#[test]
fn multiple_nodes_are_live() -> Result<(), String> {
    // allow settings to be customized when running from commandline
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            run_n_rounds_and_collect_hashes(config, Vec::new(), true);
        })
}

#[test]
fn single_node_is_live() {
    let config = ConsensusRunnerConfig {
        num_nodes: 1,
        num_rounds: 126,
        ..Default::default()
    };
    run_n_rounds_and_collect_hashes(config, Vec::new(), true);
}

#[ignore]
#[test]
fn multiple_nodes_are_deterministic() {
    let run = || {
        let config = ConsensusRunnerConfig {
            num_nodes: 4,
            num_rounds: 10,
            ..Default::default()
        };
        run_n_rounds_and_collect_hashes(config, Vec::new(), true)
    };
    assert_eq!(run(), run());
}

#[test]
fn minority_invalid_notary_share_signature_would_pass() -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            let mut rng = ChaChaRng::seed_from_u64(config.random_seed);
            let f = (config.num_nodes - 1) / 3;
            assert!(f > 0, "This test requires NUM_NODES >= 4");
            let mut malicious: Vec<ConsensusModifier> = Vec::new();
            for _ in 0..rng.gen_range(1..=f) {
                malicious.push(&malicious::InvalidNotaryShareSignature::new);
            }
            let malicious = vec![&malicious::InvalidNotaryShareSignature::new as _];
            run_n_rounds_and_collect_hashes(config, malicious, true);
        })
}

#[test]
fn majority_invalid_notary_share_signature_would_stuck() -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            let mut malicious: Vec<ConsensusModifier> = Vec::new();
            for _ in 0..(config.num_nodes / 3 + 1) {
                malicious.push(&malicious::InvalidNotaryShareSignature::new);
            }
            run_n_rounds_and_collect_hashes(config, malicious, false);
        })
}

fn run_n_rounds_and_collect_hashes(
    config: ConsensusRunnerConfig,
    mut modifiers: Vec<ConsensusModifier<'_>>,
    finish: bool,
) -> Vec<CryptoHash> {
    let nodes = config.num_nodes;
    ic_test_utilities::artifact_pool_config::with_test_pool_configs(nodes, |pool_configs| {
        let rounds = config.num_rounds;
        let hashes = Rc::new(RefCell::new(Vec::new()));
        let hashes_clone = hashes.clone();
        let reach_n_rounds = move |inst: &ConsensusInstance<'_>| {
            let pool = inst.driver.consensus_pool.write().unwrap();
            for nota in pool.validated().notarization().get_highest_iter() {
                let hash = ic_types::crypto::crypto_hash(&nota);
                let hash = hash.get_ref();
                if !hashes_clone.borrow().contains(hash) {
                    hashes_clone.borrow_mut().push(hash.clone());
                }
            }
            inst.deps.message_routing.expected_batch_height() >= Height::from(rounds)
        };
        let time_source = FastForwardTimeSource::new();
        let subnet_id = subnet_test_id(0);
        let replica_configs: Vec<_> = vec![(); nodes]
            .iter()
            .enumerate()
            .map(|(index, _)| ReplicaConfig {
                node_id: node_test_id(index as u64),
                subnet_id,
            })
            .collect();
        let node_ids: Vec<_> = replica_configs
            .iter()
            .map(|config| config.node_id)
            .collect();
        let (registry_client, cup, cryptos) = setup_subnet(subnet_id, &node_ids);
        let inst_deps: Vec<_> = replica_configs
            .iter()
            .zip(pool_configs.iter())
            .map(|(replica_config, pool_config)| {
                ConsensusDependencies::new(
                    replica_config.clone(),
                    pool_config.clone(),
                    Arc::clone(&registry_client) as Arc<dyn RegistryClient>,
                    cup.clone(),
                )
            })
            .collect();

        let mut runner = ConsensusRunner::new_with_config(config, time_source);

        for ((pool_config, deps), crypto) in pool_configs
            .iter()
            .zip(inst_deps.iter())
            .zip(cryptos.iter())
        {
            let membership = Membership::new(
                deps.consensus_pool.read().unwrap().get_cache(),
                Arc::clone(&registry_client) as Arc<dyn RegistryClient>,
                subnet_id,
            );
            let membership = Arc::new(membership);
            let modifier = modifiers.pop();
            runner.add_instance(
                membership.clone(),
                crypto.clone(),
                crypto.clone(),
                modifier,
                deps,
                pool_config.clone(),
                &PoolReader::new(&*deps.consensus_pool.read().unwrap()),
            );
        }
        assert_eq!(runner.run_until(&reach_n_rounds), finish);
        hashes.as_ref().take()
    })
}
