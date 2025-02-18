use crate::{
    cli::{print_height_info, read_optional, read_optional_version},
    error::RecoveryError,
    file_sync_helper::create_dir,
    recovery_iterator::RecoveryIterator,
    RecoveryArgs, RecoveryResult, CUPS_DIR,
};
use clap::Parser;
use ic_base_types::SubnetId;
use ic_types::ReplicaVersion;
use serde::{Deserialize, Serialize};
use slog::Logger;
use std::{iter::Peekable, net::IpAddr, path::PathBuf};
use strum::IntoEnumIterator;
use strum_macros::{EnumIter, EnumMessage, EnumString};

use crate::{Recovery, Step};

#[derive(
    Debug, Copy, Clone, EnumIter, EnumMessage, EnumString, PartialEq, Deserialize, Serialize,
)]
pub enum StepType {
    StopReplica,
    DownloadCertifications,
    MergeCertificationPools,
    DownloadState,
    ICReplay,
    ValidateReplayOutput,
    UpdateRegistryLocalStore,
    CreateTars,
    CopyIcState,
    GetRecoveryCUP,
    UploadCUPandRegistry,
    WaitForCUP,
    UploadState,
    Cleanup,
}

#[derive(Debug, Clone, PartialEq, Parser, Deserialize, Serialize)]
#[clap(version = "1.0")]
pub struct NNSRecoverySameNodesArgs {
    /// Id of the broken subnet
    #[clap(long, parse(try_from_str=crate::util::subnet_id_from_str))]
    pub subnet_id: SubnetId,

    /// Replica version to upgrade the broken subnet to
    #[clap(long, parse(try_from_str=::std::convert::TryFrom::try_from))]
    pub upgrade_version: Option<ReplicaVersion>,

    /// IP address of the node to download the subnet state from. Should be different to node used in nns-url.
    #[clap(long)]
    pub download_node: Option<IpAddr>,

    /// IP address of the node to upload the new subnet state to
    #[clap(long)]
    pub upload_node: Option<IpAddr>,

    /// If present the tool will start execution for the provided step, skipping the initial ones
    #[clap(long = "resume")]
    pub next_step: Option<StepType>,
}

pub struct NNSRecoverySameNodes {
    step_iterator: Peekable<StepTypeIter>,
    pub params: NNSRecoverySameNodesArgs,
    pub recovery_args: RecoveryArgs,
    pub recovery: Recovery,
    interactive: bool,
    logger: Logger,
    new_state_dir: PathBuf,
}

impl NNSRecoverySameNodes {
    pub fn new(
        logger: Logger,
        recovery_args: RecoveryArgs,
        subnet_args: NNSRecoverySameNodesArgs,
        interactive: bool,
    ) -> Self {
        let recovery = Recovery::new(
            logger.clone(),
            recovery_args.clone(),
            /*neuron_args=*/ None,
        )
        .expect("Failed to init recovery");
        recovery.init_registry_local_store();
        let new_state_dir = recovery.work_dir.join("new_ic_state");
        create_dir(&new_state_dir).expect("Failed to create state directory for upload.");
        Self {
            step_iterator: StepType::iter().peekable(),
            params: subnet_args,
            recovery_args,
            recovery,
            logger,
            new_state_dir,
            interactive,
        }
    }

    pub fn get_recovery_api(&self) -> &Recovery {
        &self.recovery
    }
}

impl RecoveryIterator<StepType, StepTypeIter> for NNSRecoverySameNodes {
    fn get_step_iterator(&mut self) -> &mut Peekable<StepTypeIter> {
        &mut self.step_iterator
    }

    fn store_next_step(&mut self, step_type: Option<StepType>) {
        self.params.next_step = step_type;
    }

    fn get_logger(&self) -> &Logger {
        &self.logger
    }

    fn interactive(&self) -> bool {
        self.interactive
    }

    fn read_step_params(&mut self, step_type: StepType) {
        match step_type {
            StepType::StopReplica => {
                print_height_info(
                    &self.logger,
                    self.recovery.registry_client.clone(),
                    self.params.subnet_id,
                );

                if self.params.download_node.is_none() {
                    self.params.download_node = read_optional(&self.logger, "Enter download IP:");
                }
            }

            StepType::ICReplay => {
                if self.params.upgrade_version.is_none() {
                    self.params.upgrade_version =
                        read_optional_version(&self.logger, "Upgrade version: ");
                }
            }

            StepType::WaitForCUP => {
                if self.params.upload_node.is_none() {
                    self.params.upload_node = read_optional(&self.logger, "Enter upload IP:");
                }
            }

            _ => {}
        }
    }

    fn get_step_impl(&self, step_type: StepType) -> RecoveryResult<Box<dyn Step>> {
        match step_type {
            StepType::StopReplica => {
                if let Some(node_ip) = self.params.download_node {
                    Ok(Box::new(self.recovery.get_stop_replica_step(node_ip)))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::DownloadCertifications => Ok(Box::new(
                self.recovery
                    .get_download_certs_step(self.params.subnet_id, true),
            )),

            StepType::MergeCertificationPools => {
                Ok(Box::new(self.recovery.get_merge_certification_pools_step()))
            }

            StepType::DownloadState => {
                if let Some(node_ip) = self.params.download_node {
                    Ok(Box::new(self.recovery.get_download_state_step(
                        node_ip,
                        /*try_readonly=*/ false,
                        /*keep_downloaded_state=*/ false,
                        /*additional_excludes=*/ vec![CUPS_DIR],
                    )))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::ICReplay => {
                if let Some(upgrade_version) = self.params.upgrade_version.clone() {
                    Ok(Box::new(self.recovery.get_replay_with_upgrade_step(
                        self.params.subnet_id,
                        upgrade_version,
                    )?))
                } else {
                    Ok(Box::new(self.recovery.get_replay_step(
                        self.params.subnet_id,
                        None,
                        None,
                    )))
                }
            }
            StepType::ValidateReplayOutput => Ok(Box::new(self.recovery.get_validate_replay_step(
                self.params.subnet_id,
                u64::from(self.params.upgrade_version.is_some()),
            ))),

            StepType::UpdateRegistryLocalStore => {
                if self.params.upgrade_version.is_none() {
                    Err(RecoveryError::StepSkipped)
                } else {
                    Ok(Box::new(
                        self.recovery
                            .get_update_local_store_step(self.params.subnet_id),
                    ))
                }
            }

            StepType::CreateTars => Ok(Box::new(self.recovery.get_create_tars_step())),

            StepType::CopyIcState => Ok(Box::new(
                self.recovery.get_copy_ic_state(self.new_state_dir.clone()),
            )),

            StepType::GetRecoveryCUP => Ok(Box::new(
                self.recovery.get_recovery_cup_step(self.params.subnet_id)?,
            )),

            StepType::UploadCUPandRegistry => Ok(Box::new(
                self.recovery
                    .get_upload_cup_and_tar_step(self.params.subnet_id),
            )),

            StepType::WaitForCUP => {
                if let Some(node_ip) = self.params.upload_node {
                    Ok(Box::new(self.recovery.get_wait_for_cup_step(node_ip)))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::UploadState => {
                if let Some(node_ip) = self.params.upload_node {
                    Ok(Box::new(
                        self.recovery.get_upload_and_restart_step_with_data_src(
                            node_ip,
                            self.new_state_dir.clone(),
                        ),
                    ))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::Cleanup => Ok(Box::new(self.recovery.get_cleanup_step())),
        }
    }
}
