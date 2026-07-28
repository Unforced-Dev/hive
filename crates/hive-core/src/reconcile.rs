//! Making reality match the specs.
//!
//! [`plan`] is a pure function of desired and observed state. It performs no
//! I/O, which is deliberate: reconciliation logic is where a runtime destroys
//! things, and it should be possible to test every destructive decision without
//! a container runtime present.
//!
//! Applying a plan is [`apply`], which is the only part that touches Docker.

use crate::backend::{ContainerBackend, Observed};

/// Restarts before hive stops trying and reports the agent as stuck.
///
/// Something must bound this. A container that fails on startup — bad
/// credential, missing harness, malformed config — will restart forever under
/// `unless-stopped`, and a reconciler that responds by recreating it turns a
/// broken agent into an unbounded loop of image pulls and log noise, which is
/// how one bad spec takes out a box.
pub const CRASH_LOOP_THRESHOLD: u32 = 5;

/// An agent hive should be running, reduced to what reconciliation needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Desired {
    pub name: String,
    pub spec_hash: String,
    pub readiness: Readiness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Readiness {
    Ready,
    /// Broker keys the agent needs that the broker does not hold.
    MissingCredentials(Vec<String>),
    /// This spec conflicts with another one. Held rather than dropped, so a bad
    /// new spec cannot tear down a working agent — see [`HoldReason::Conflict`].
    Conflict(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// No container exists for this agent.
    Create { agent: String },
    /// A container exists but does not match the spec. Containers are largely
    /// immutable — memory, environment, network and command cannot be changed
    /// in place — so the only honest response to a changed spec is replacement.
    Replace { agent: String, reason: ReplaceReason },
    /// The container matches and is merely stopped.
    Start { agent: String },
    /// A container exists for which there is no spec.
    Remove { agent: String },
    /// Something is wrong and hive is deliberately not acting.
    Hold { agent: String, reason: HoldReason },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplaceReason {
    SpecChanged { from: String, to: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldReason {
    /// Restarting repeatedly. Recreating would not fix it and would hide it.
    CrashLooping { restarts: u32, exit_code: Option<i64> },
    /// Starting the agent would produce one that runs and cannot work.
    MissingCredentials(Vec<String>),
    /// Two specs disagree in a way that makes both unsafe to act on — the same
    /// identity on the same relay, for instance.
    ///
    /// HELD, not removed. Dropping the conflicting specs entirely would make
    /// them look deleted to the reconciler, which would then tear down a
    /// container that had been running correctly for weeks. A typo in a new file
    /// must not take down a working agent.
    Conflict(String),
}

impl Action {
    pub fn agent(&self) -> &str {
        match self {
            Self::Create { agent }
            | Self::Replace { agent, .. }
            | Self::Start { agent }
            | Self::Remove { agent }
            | Self::Hold { agent, .. } => agent,
        }
    }

    /// Whether this action destroys a container. Used by the CLI to require
    /// confirmation in dry-run mode, and by the daemon's audit log.
    pub fn is_destructive(&self) -> bool {
        matches!(self, Self::Replace { .. } | Self::Remove { .. })
    }
}

/// Decide what to do. Pure.
///
/// `observed` must already be filtered to containers hive manages; the backend's
/// label filter does that, and it is what stops reconciliation from deleting
/// containers a human created.
pub fn plan(desired: &[Desired], observed: &[Observed]) -> Vec<Action> {
    let mut actions = Vec::new();

    for d in desired {
        let existing = observed.iter().find(|o| o.agent == d.name);

        // Credentials are checked BEFORE anything is created. An agent that
        // starts without its credentials does not fail — it comes up, joins the
        // relay, and answers wrongly or not at all. That is much harder to
        // attribute than a deploy that refuses with a named missing key.
        match &d.readiness {
            Readiness::MissingCredentials(keys) => {
                actions.push(Action::Hold {
                    agent: d.name.clone(),
                    reason: HoldReason::MissingCredentials(keys.clone()),
                });
                continue;
            }
            Readiness::Conflict(why) => {
                actions.push(Action::Hold {
                    agent: d.name.clone(),
                    reason: HoldReason::Conflict(why.clone()),
                });
                continue;
            }
            Readiness::Ready => {}
        }

        match existing {
            None => actions.push(Action::Create { agent: d.name.clone() }),

            Some(o) if o.spec_hash != d.spec_hash => actions.push(Action::Replace {
                agent: d.name.clone(),
                reason: ReplaceReason::SpecChanged {
                    from: o.spec_hash.clone(),
                    to: d.spec_hash.clone(),
                },
            }),

            // Matches the spec but is restarting repeatedly. Replacing it would
            // produce an identical container that fails identically, while
            // resetting the restart counter that is the only evidence of the
            // problem.
            Some(o) if o.restarts >= CRASH_LOOP_THRESHOLD => actions.push(Action::Hold {
                agent: d.name.clone(),
                reason: HoldReason::CrashLooping {
                    restarts: o.restarts,
                    exit_code: o.exit_code,
                },
            }),

            Some(o) if !o.running => actions.push(Action::Start { agent: d.name.clone() }),

            // Matches and is running.
            Some(_) => {}
        }
    }

    // Containers with no spec. Specs are the single source of truth, so an agent
    // deleted from disk is an agent that should stop existing — but only its
    // CONTAINER. The state volume, holding its credentials and any interactive
    // OAuth session, is never touched here.
    for o in observed {
        if !desired.iter().any(|d| d.name == o.agent) {
            actions.push(Action::Remove { agent: o.agent.clone() });
        }
    }

    actions
}

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("no plan builder registered for agent '{0}'")]
    NoPlanFor(String),
    #[error(transparent)]
    Backend(#[from] crate::backend::BackendError),
}

/// The outcome of applying one action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub action: Action,
    pub error: Option<String>,
}

/// Apply a plan.
///
/// `build` produces the container plan for an agent, lazily — it is called only
/// for agents that are actually being created, so that rendering config and
/// fetching credentials does not happen for agents that need no change.
///
/// One agent's failure does not abort the others. A reconciler that stops at the
/// first error leaves the rest of the box in an arbitrary half-state depending on
/// iteration order, and the second problem is only discovered after the first is
/// fixed.
pub fn apply<B, F>(backend: &B, actions: Vec<Action>, mut build: F) -> Vec<Outcome>
where
    B: ContainerBackend,
    F: FnMut(&str) -> Result<crate::backend::ContainerPlan, ApplyError>,
{
    use crate::backend::Names;

    let mut outcomes = Vec::new();
    for action in actions {
        let agent = action.agent().to_string();
        let result: Result<(), ApplyError> = (|| {
            match &action {
                Action::Create { .. } => {
                    backend.ensure_network(&Names::network(&agent))?;
                    backend.ensure_volume(&Names::volume(&agent))?;
                    backend.create_and_start(&build(&agent)?)?;
                }
                Action::Replace { .. } => {
                    // Build BEFORE removing. If rendering config or fetching a
                    // credential fails, the old container is still running —
                    // a degraded agent beats no agent, and the error is
                    // reported rather than compounded.
                    let plan = build(&agent)?;
                    backend.remove(&Names::container(&agent))?;
                    backend.ensure_network(&Names::network(&agent))?;
                    backend.ensure_volume(&Names::volume(&agent))?;
                    backend.create_and_start(&plan)?;
                }
                Action::Start { .. } => {
                    // Recreated rather than `docker start`ed: config and
                    // credentials are injected between create and start, and a
                    // plain start would reuse whatever was injected last time.
                    // For a container stopped across a broker rotation, that is
                    // a stale secret.
                    let plan = build(&agent)?;
                    backend.remove(&Names::container(&agent))?;
                    backend.create_and_start(&plan)?;
                }
                Action::Remove { .. } => {
                    // Container only. The volume outlives it.
                    backend.remove(&Names::container(&agent))?;
                }
                Action::Hold { .. } => {}
            }
            Ok(())
        })();

        outcomes.push(Outcome {
            action,
            error: result.err().map(|e| e.to_string()),
        });
    }
    outcomes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(agent: &str, hash: &str, running: bool, restarts: u32) -> Observed {
        Observed {
            id: format!("id-{agent}"),
            name: format!("hive-{agent}"),
            agent: agent.into(),
            spec_hash: hash.into(),
            running,
            restarts,
            exit_code: if running { None } else { Some(1) },
        }
    }

    fn ready(name: &str, hash: &str) -> Desired {
        Desired { name: name.into(), spec_hash: hash.into(), readiness: Readiness::Ready }
    }

    #[test]
    fn a_new_spec_creates_a_container() {
        let a = plan(&[ready("alice", "h1")], &[]);
        assert_eq!(a, vec![Action::Create { agent: "alice".into() }]);
    }

    #[test]
    fn an_unchanged_running_agent_is_left_alone() {
        // Reconciliation runs continuously. If a matching agent produced any
        // action, every pass would restart every agent.
        let a = plan(&[ready("alice", "h1")], &[observed("alice", "h1", true, 0)]);
        assert!(a.is_empty(), "expected no actions, got {a:?}");
    }

    #[test]
    fn a_changed_spec_replaces_rather_than_mutates() {
        // Memory, env, network and command cannot be changed on a live
        // container. Pretending otherwise yields a container that reports the
        // new spec hash and runs the old configuration.
        let a = plan(&[ready("alice", "h2")], &[observed("alice", "h1", true, 0)]);
        assert_eq!(
            a,
            vec![Action::Replace {
                agent: "alice".into(),
                reason: ReplaceReason::SpecChanged { from: "h1".into(), to: "h2".into() },
            }]
        );
    }

    #[test]
    fn a_deleted_spec_removes_the_container_and_says_nothing_about_the_volume() {
        // The volume holds credentials and any interactive OAuth session. Losing
        // it to a spec edit would send the agent back logged out, hours later,
        // for reasons no one would connect to the edit.
        let a = plan(&[], &[observed("ghost", "h1", true, 0)]);
        assert_eq!(a, vec![Action::Remove { agent: "ghost".into() }]);
        assert!(a[0].is_destructive());
    }

    #[test]
    fn a_crash_looping_agent_is_held_not_recreated() {
        // Recreating produces an identical container that fails identically, and
        // resets the restart count — destroying the only evidence that anything
        // is wrong. Unbounded, it is also how one bad spec saturates a box.
        let a = plan(
            &[ready("alice", "h1")],
            &[observed("alice", "h1", false, CRASH_LOOP_THRESHOLD)],
        );
        assert!(matches!(
            a.as_slice(),
            [Action::Hold { reason: HoldReason::CrashLooping { .. }, .. }]
        ));
    }

    #[test]
    fn a_crash_loop_wins_over_merely_being_stopped() {
        // Both conditions are true at once; treating it as "just stopped" would
        // restart it forever.
        let a = plan(&[ready("a", "h1")], &[observed("a", "h1", false, 99)]);
        assert!(matches!(a[0], Action::Hold { .. }), "got {a:?}");
    }

    #[test]
    fn a_changed_spec_wins_over_a_crash_loop() {
        // Ordering the other way would strand an agent whose crash the spec edit
        // is trying to FIX — the operator changes the spec, and hive refuses to
        // apply it because the old container is failing.
        let a = plan(&[ready("a", "h2")], &[observed("a", "h1", false, 99)]);
        assert!(matches!(a[0], Action::Replace { .. }), "got {a:?}");
    }

    #[test]
    fn missing_credentials_hold_before_anything_is_created() {
        // An agent started without credentials does not fail. It comes up, joins
        // the relay, and answers wrongly or not at all — the most expensive
        // possible failure mode to attribute.
        let d = Desired {
            name: "alice".into(),
            spec_hash: "h1".into(),
            readiness: Readiness::MissingCredentials(vec!["nsec/alice".into()]),
        };
        let a = plan(&[d], &[]);
        assert!(matches!(
            a.as_slice(),
            [Action::Hold { reason: HoldReason::MissingCredentials(_), .. }]
        ));
        assert!(!a[0].is_destructive());
    }

    #[test]
    fn a_conflicting_spec_is_held_and_never_removes_a_running_container() {
        // Two specs claiming one identity on one relay. Both are held. Crucially
        // NEITHER is removed: dropping them from the desired set would make the
        // already-running container look deleted, so adding one bad file would
        // tear down an agent that had been working for weeks.
        let d = vec![
            Desired {
                name: "uni-home".into(),
                spec_hash: "h1".into(),
                readiness: Readiness::Conflict("same identity, same relay".into()),
            },
            Desired {
                name: "uni-dupe".into(),
                spec_hash: "h2".into(),
                readiness: Readiness::Conflict("same identity, same relay".into()),
            },
        ];
        let actions = plan(&d, &[observed("uni-home", "h1", true, 0)]);
        assert!(
            actions.iter().all(|a| matches!(a, Action::Hold { .. })),
            "a conflict must not create or destroy anything: {actions:?}"
        );
        assert!(
            !actions.iter().any(|a| a.is_destructive()),
            "the running container was torn down by a conflicting NEW spec"
        );
    }

    #[test]
    fn a_stopped_matching_agent_is_started() {
        let a = plan(&[ready("alice", "h1")], &[observed("alice", "h1", false, 0)]);
        assert_eq!(a, vec![Action::Start { agent: "alice".into() }]);
    }

    #[test]
    fn unrelated_agents_are_planned_independently() {
        // One bad agent must not suppress work on the others.
        let a = plan(
            &[ready("alice", "h1"), ready("bob", "h2")],
            &[observed("alice", "h1", true, 0), observed("carol", "h9", true, 0)],
        );
        assert!(a.contains(&Action::Create { agent: "bob".into() }));
        assert!(a.contains(&Action::Remove { agent: "carol".into() }));
        assert!(!a.iter().any(|x| x.agent() == "alice"));
    }
}
