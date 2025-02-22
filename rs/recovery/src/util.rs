use crate::error::{RecoveryError, RecoveryResult};
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use slog::{o, Drain, Logger};
use std::{future::Future, str::FromStr};
use tokio::runtime::Runtime;

pub fn block_on<F: Future>(f: F) -> F::Output {
    let rt = Runtime::new().unwrap_or_else(|err| panic!("Could not create tokio runtime: {}", err));
    rt.block_on(f)
}

pub fn parse_hex_str(string: &str) -> RecoveryResult<u64> {
    u64::from_str_radix(string, 16).map_err(|e| {
        RecoveryError::invalid_output_error(format!(
            "Could not read checkpoint height from dir name '{}': {}",
            string, e
        ))
    })
}

pub fn subnet_id_from_str(s: &str) -> Result<SubnetId, String> {
    PrincipalId::from_str(s)
        .map_err(|e| format!("Unable to parse subnet_id {:?}", e))
        .map(SubnetId::from)
}

pub fn node_id_from_str(s: &str) -> Result<NodeId, String> {
    PrincipalId::from_str(s)
        .map_err(|e| format!("Unable to parse node_id {:?}", e))
        .map(NodeId::from)
}

pub fn make_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    slog::Logger::root(drain, o!())
}
