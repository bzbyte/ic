use ic_base_types::{NumBytes, NumSeconds};
use ic_error_types::{ErrorCode, UserError};
use ic_ic00_types::CanisterSettingsArgs;
use ic_types::{
    ComputeAllocation, InvalidComputeAllocationError, InvalidMemoryAllocationError,
    MemoryAllocation, PrincipalId,
};
use num_traits::cast::ToPrimitive;
use std::convert::TryFrom;

/// Struct used for decoding CanisterSettingsArgs
#[derive(Default)]
pub(crate) struct CanisterSettings {
    pub(crate) controller: Option<PrincipalId>,
    pub(crate) controllers: Option<Vec<PrincipalId>>,
    pub(crate) compute_allocation: Option<ComputeAllocation>,
    pub(crate) memory_allocation: Option<MemoryAllocation>,
    pub(crate) freezing_threshold: Option<NumSeconds>,
}

impl CanisterSettings {
    pub fn new(
        controller: Option<PrincipalId>,
        controllers: Option<Vec<PrincipalId>>,
        compute_allocation: Option<ComputeAllocation>,
        memory_allocation: Option<MemoryAllocation>,
        freezing_threshold: Option<NumSeconds>,
    ) -> Self {
        Self {
            controller,
            controllers,
            compute_allocation,
            memory_allocation,
            freezing_threshold,
        }
    }

    pub fn controller(&self) -> Option<PrincipalId> {
        self.controller
    }

    pub fn controllers(&self) -> Option<Vec<PrincipalId>> {
        self.controllers.clone()
    }

    pub fn compute_allocation(&self) -> Option<ComputeAllocation> {
        self.compute_allocation
    }

    pub fn memory_allocation(&self) -> Option<MemoryAllocation> {
        self.memory_allocation
    }

    pub fn freezing_threshold(&self) -> Option<NumSeconds> {
        self.freezing_threshold
    }
}

impl TryFrom<CanisterSettingsArgs> for CanisterSettings {
    type Error = UpdateSettingsError;

    fn try_from(input: CanisterSettingsArgs) -> Result<Self, Self::Error> {
        let controller = input.get_controller();
        let compute_allocation = match input.compute_allocation {
            Some(ca) => Some(ComputeAllocation::try_from(ca.0.to_u64().ok_or_else(
                || UpdateSettingsError::ComputeAllocation(InvalidComputeAllocationError::new(ca)),
            )?)?),
            None => None,
        };

        let memory_allocation = match input.memory_allocation {
            Some(ma) => Some(MemoryAllocation::try_from(NumBytes::from(
                ma.0.to_u64().ok_or_else(|| {
                    UpdateSettingsError::MemoryAllocation(InvalidMemoryAllocationError::new(ma))
                })?,
            ))?),
            None => None,
        };

        let freezing_threshold = match input.freezing_threshold {
            Some(ft) => Some(NumSeconds::from(ft.0.to_u64().ok_or(
                UpdateSettingsError::FreezingThresholdOutOfRange { provided: ft },
            )?)),
            None => None,
        };

        Ok(CanisterSettings::new(
            controller,
            input.controllers,
            compute_allocation,
            memory_allocation,
            freezing_threshold,
        ))
    }
}

impl TryFrom<Option<CanisterSettingsArgs>> for CanisterSettings {
    type Error = UpdateSettingsError;

    fn try_from(input: Option<CanisterSettingsArgs>) -> Result<Self, Self::Error> {
        match input {
            Some(settings) => CanisterSettings::try_from(settings),
            None => Ok(CanisterSettings::default()),
        }
    }
}

pub(crate) struct CanisterSettingsBuilder {
    controller: Option<PrincipalId>,
    controllers: Option<Vec<PrincipalId>>,
    compute_allocation: Option<ComputeAllocation>,
    memory_allocation: Option<MemoryAllocation>,
    freezing_threshold: Option<NumSeconds>,
}

#[allow(dead_code)]
impl CanisterSettingsBuilder {
    pub fn new() -> Self {
        Self {
            controller: None,
            controllers: None,
            compute_allocation: None,
            memory_allocation: None,
            freezing_threshold: None,
        }
    }

    pub fn build(self) -> CanisterSettings {
        CanisterSettings {
            controller: self.controller,
            controllers: self.controllers,
            compute_allocation: self.compute_allocation,
            memory_allocation: self.memory_allocation,
            freezing_threshold: self.freezing_threshold,
        }
    }

    pub fn with_controller(self, controller: PrincipalId) -> Self {
        Self {
            controller: Some(controller),
            ..self
        }
    }

    pub fn with_controllerr(self, controllers: Vec<PrincipalId>) -> Self {
        Self {
            controllers: Some(controllers),
            ..self
        }
    }

    pub fn with_compute_allocation(self, compute_allocation: ComputeAllocation) -> Self {
        Self {
            compute_allocation: Some(compute_allocation),
            ..self
        }
    }

    pub fn with_memory_allocation(self, memory_allocation: MemoryAllocation) -> Self {
        Self {
            memory_allocation: Some(memory_allocation),
            ..self
        }
    }

    pub fn with_freezing_threshold(self, freezing_threshold: NumSeconds) -> Self {
        Self {
            freezing_threshold: Some(freezing_threshold),
            ..self
        }
    }
}

pub enum UpdateSettingsError {
    ComputeAllocation(InvalidComputeAllocationError),
    MemoryAllocation(InvalidMemoryAllocationError),
    FreezingThresholdOutOfRange { provided: candid::Nat },
}

impl From<UpdateSettingsError> for UserError {
    fn from(err: UpdateSettingsError) -> Self {
        match err {
            UpdateSettingsError::ComputeAllocation(err) => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "ComputeAllocation expected to be in the range [{}..{}], got {}",
                    err.min(),
                    err.max(),
                    err.given()
                ),
            ),
            UpdateSettingsError::MemoryAllocation(err) => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "MemoryAllocation expected to be in the range [{}..{}], got {}",
                    err.min, err.max, err.given
                ),
            ),
            UpdateSettingsError::FreezingThresholdOutOfRange { provided } => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "Freezing threshold expected to be in the range of [0..2^64-1], got {}",
                    provided
                ),
            ),
        }
    }
}

impl From<InvalidComputeAllocationError> for UpdateSettingsError {
    fn from(err: InvalidComputeAllocationError) -> Self {
        Self::ComputeAllocation(err)
    }
}

impl From<InvalidMemoryAllocationError> for UpdateSettingsError {
    fn from(err: InvalidMemoryAllocationError) -> Self {
        Self::MemoryAllocation(err)
    }
}
