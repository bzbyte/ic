#![no_main]
use ic_config::{embedders::Config, flag_status::FlagStatus, subnet_config::SchedulerConfig};
use ic_embedders::{
    wasm_executor::{WasmExecutor, WasmExecutorImpl},
    CompilationCache, WasmExecutionInput, WasmtimeEmbedder,
};
use ic_interfaces::execution_environment::{ExecutionMode, SubnetAvailableMemory};
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::execution_state::{WasmBinary, WasmMetadata},
    page_map::TestPageAllocatorFileDescriptorImpl,
    ExecutionState, ExportedFunctions, Global, Memory, NetworkTopology,
};
use ic_system_api::{
    sandbox_safe_system_state::SandboxSafeSystemState, ApiType, ExecutionParameters,
    InstructionLimits,
};
use ic_test_utilities::{
    cycles_account_manager::CyclesAccountManagerBuilder, mock_time, state::SystemStateBuilder,
    types::ids::user_test_id,
};
use ic_types::{
    methods::{FuncRef, WasmMethod},
    ComputeAllocation, NumBytes, NumInstructions,
};
use ic_wasm_types::CanisterModule;

use libfuzzer_sys::fuzz_target;
use std::{collections::BTreeSet, path::PathBuf, sync::Arc};
mod ic_wasm;
use ic_wasm::ICWasmConfig;
use wasm_smith::ConfiguredModule;

// The fuzzer creates valid wasms and tries to execute a query method via WasmExecutor.
// The fuzzing success rate directly depends upon the IC valid wasm corpus provided.
// The fuzz test is only compiled but not executed by CI.
//
// To execute the fuzzer run
// bazel run --config=fuzzing --build_tag_filters=fuzz_test //rs/embedders/fuzz:execute_with_wasm_executor -- corpus/

fuzz_target!(|module: ConfiguredModule<ICWasmConfig>| {
    let wasm = module.module.to_bytes();
    let canister_module = CanisterModule::new(wasm);
    let wasm_binary = WasmBinary::new(canister_module);

    let wasm_method = WasmMethod::Query("test".to_string());
    let func_ref = FuncRef::Method(wasm_method.clone());
    let wasm_methods = BTreeSet::from([wasm_method]);

    let embedder_config = Config::default();
    let log = no_op_logger();
    let metrics_registry = MetricsRegistry::new();
    let fd_factory = Arc::new(TestPageAllocatorFileDescriptorImpl::new());

    let wasm_executor = WasmExecutorImpl::new(
        WasmtimeEmbedder::new(embedder_config, log.clone()),
        &metrics_registry,
        log,
        fd_factory,
    );

    let execution_state = setup_execution_state(wasm_binary, wasm_methods);
    let wasm_execution_input = setup_wasm_execution_input(func_ref);
    let (_compilation_result, _execution_result) =
        Arc::new(wasm_executor).execute(wasm_execution_input, &execution_state);
});

fn setup_wasm_execution_input(func_ref: FuncRef) -> WasmExecutionInput {
    const DEFAULT_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(5_000_000_000);

    let time = mock_time();
    let api_type = ApiType::init(time, vec![], user_test_id(24).get());

    let system_state = SystemStateBuilder::default().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let dirty_page_overhead = SchedulerConfig::application_subnet().dirty_page_overhead;
    let network_topology = NetworkTopology::default();

    let sandbox_safe_system_state = SandboxSafeSystemState::new(
        &system_state,
        cycles_account_manager,
        &network_topology,
        dirty_page_overhead,
    );

    let canister_current_memory_usage = NumBytes::new(0);

    let execution_parameters = ExecutionParameters {
        instruction_limits: InstructionLimits::new(
            FlagStatus::Disabled,
            DEFAULT_NUM_INSTRUCTIONS,
            DEFAULT_NUM_INSTRUCTIONS,
        ),
        canister_memory_limit: NumBytes::from(4 << 30),
        compute_allocation: ComputeAllocation::default(),
        subnet_type: SubnetType::Application,
        execution_mode: ExecutionMode::Replicated,
    };

    let subnet_available_memory =
        SubnetAvailableMemory::new(i64::MAX / 2, i64::MAX / 2, i64::MAX / 2);

    let compilation_cache = Arc::new(CompilationCache::new(NumBytes::new(0)));

    WasmExecutionInput {
        api_type,
        sandbox_safe_system_state,
        canister_current_memory_usage,
        execution_parameters,
        subnet_available_memory,
        func_ref,
        compilation_cache,
    }
}

fn setup_execution_state(
    wasm_binary: Arc<WasmBinary>,
    wasm_methods: BTreeSet<WasmMethod>,
) -> ExecutionState {
    // TODO (PSEC-1204)
    // Get the globals and exported functions from the wasm module before initializing
    // the execution state
    ExecutionState::new(
        PathBuf::new(),
        wasm_binary,
        ExportedFunctions::new(wasm_methods),
        Memory::new_for_testing(),
        Memory::new_for_testing(),
        vec![Global::I64(0)],
        WasmMetadata::default(),
    )
}
