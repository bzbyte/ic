use std::cmp::Reverse;

use certificate_orchestrator_interface::{Id, Registration};
use ic_cdk::caller;
use ic_stable_structures::StableBTreeMap;
use priority_queue::PriorityQueue;

cfg_if::cfg_if! {
    if #[cfg(test)] {
        use tests::time as time;
    } else {
        use ic_cdk::api::time;
    }
}

use crate::{
    acl::{Authorize, AuthorizeError, WithAuthorize},
    LocalRef, Memory, IN_PROGRESS_TTL,
};

#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("Not found")]
    NotFound,
    #[error("Unauthorized")]
    Unauthorized,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Queue {
    fn queue(&self, id: String, timestamp: u64) -> Result<(), QueueError>;
}

pub struct Queuer {
    tasks: LocalRef<PriorityQueue<String, Reverse<u64>>>,
    registrations: LocalRef<StableBTreeMap<Memory, Id, Registration>>,
}

impl Queuer {
    pub fn new(
        tasks: LocalRef<PriorityQueue<String, Reverse<u64>>>,
        registrations: LocalRef<StableBTreeMap<Memory, Id, Registration>>,
    ) -> Self {
        Self {
            tasks,
            registrations,
        }
    }
}

impl Queue for Queuer {
    fn queue(&self, id: String, timestamp: u64) -> Result<(), QueueError> {
        self.registrations.with(|regs| {
            let regs = regs.borrow();
            regs.get(&id).ok_or(QueueError::NotFound)
        })?;

        self.tasks.with(|tasks| {
            let mut tasks = tasks.borrow_mut();
            tasks.push(id, Reverse(timestamp));
        });

        Ok(())
    }
}

impl<T: Queue, A: Authorize> Queue for WithAuthorize<T, A> {
    fn queue(&self, id: Id, timestamp: u64) -> Result<(), QueueError> {
        if let Err(err) = self.1.authorize(&caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => QueueError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => QueueError::UnexpectedError(err),
            });
        };

        self.0.queue(id, timestamp)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DispenseError {
    #[error("No tasks available")]
    NoTasksAvailable,
    #[error("Unauthorized")]
    Unauthorized,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Dispense {
    fn dispense(&self) -> Result<Id, DispenseError>;
    fn peek(&self) -> Result<Id, DispenseError>;
}

pub struct Dispenser {
    tasks: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
    retries: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
}

impl Dispenser {
    pub fn new(
        tasks: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
        retries: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
    ) -> Self {
        Self { tasks, retries }
    }
}

impl Dispense for Dispenser {
    fn dispense(&self) -> Result<Id, DispenseError> {
        self.tasks.with(|tasks| {
            // Check for available task
            match tasks.borrow().peek() {
                None => return Err(DispenseError::NoTasksAvailable),
                Some((_, Reverse(timestamp))) => {
                    if time().lt(timestamp) {
                        return Err(DispenseError::NoTasksAvailable);
                    }
                }
            };

            // Pop task
            let id = match tasks.borrow_mut().pop() {
                None => return Err(DispenseError::NoTasksAvailable),
                Some((id, _)) => id,
            };

            // Schedule a retry in case the task failed and was not re-queued
            self.retries.with(|retries| {
                retries.borrow_mut().push(
                    id.to_owned(),
                    Reverse(time() + IN_PROGRESS_TTL.as_nanos() as u64),
                )
            });

            Ok(id)
        })
    }

    fn peek(&self) -> Result<Id, DispenseError> {
        self.tasks.with(|tasks| {
            // Check for available task
            match tasks.borrow().peek() {
                None => Err(DispenseError::NoTasksAvailable),
                Some((id, Reverse(timestamp))) => {
                    if time().lt(timestamp) {
                        return Err(DispenseError::NoTasksAvailable);
                    }
                    Ok(id.clone())
                }
            }
        })
    }
}

impl<T: Dispense, A: Authorize> Dispense for WithAuthorize<T, A> {
    fn dispense(&self) -> Result<Id, DispenseError> {
        if let Err(err) = self.1.authorize(&caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => DispenseError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => DispenseError::UnexpectedError(err),
            });
        };

        self.0.dispense()
    }

    fn peek(&self) -> Result<Id, DispenseError> {
        if let Err(err) = self.1.authorize(&caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => DispenseError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => DispenseError::UnexpectedError(err),
            });
        };

        self.0.peek()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RetryError {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Retry {
    fn retry(&self, t: u64) -> Result<(), RetryError>;
}

pub struct Retrier {
    tasks: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
    retries: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
}

impl Retrier {
    pub fn new(
        tasks: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
        retries: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
    ) -> Self {
        Self { tasks, retries }
    }
}

impl Retry for Retrier {
    fn retry(&self, t: u64) -> Result<(), RetryError> {
        self.retries.with(|retries| {
            let mut retries = retries.borrow_mut();

            #[allow(clippy::while_let_loop)]
            loop {
                // Check for next retry
                let p = match retries.peek() {
                    Some((_, p)) => p.0,
                    None => break,
                };

                if p > t {
                    break;
                }

                let id = match retries.pop() {
                    Some((id, _)) => id,
                    None => break,
                };

                // Schedule a task for the ID
                self.tasks.with(|tasks| {
                    let mut tasks = tasks.borrow_mut();
                    tasks.push(id, Reverse(t));
                });
            }

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{RETRIES, TASKS};

    pub fn time() -> u64 {
        0
    }

    #[test]
    fn dispense_empty() {
        match Dispenser::new(&TASKS, &RETRIES).dispense() {
            Err(DispenseError::NoTasksAvailable) => {}
            _ => panic!("Not the error that was expected."),
        };
    }

    #[test]
    fn dispense_ok() {
        TASKS.with(|t| {
            t.borrow_mut().push(
                "id".into(), // item
                Reverse(0),  // priority
            )
        });

        let id = match Dispenser::new(&TASKS, &RETRIES).dispense() {
            Ok(id) => id,
            other => panic!("expected id but got {other:?}"),
        };

        assert_eq!(id, "id");
    }

    #[test]
    fn dispense_unavailable() {
        TASKS.with(|t| {
            t.borrow_mut().push(
                "id".into(), // item
                Reverse(1),  // priority
            )
        });

        match Dispenser::new(&TASKS, &RETRIES).dispense() {
            Err(DispenseError::NoTasksAvailable) => {}
            other => panic!("expected NoTasksAvailable but got {other:?}"),
        };
    }
}
