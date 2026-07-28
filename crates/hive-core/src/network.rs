//! Network policy for agent containers.
//!
//! An agent gets: the public internet, a named allow-list of endpoints on the
//! host, and nothing else — no other agent, no other Docker network, no other
//! node on the private network, no other host port.
//!
//! Every rule below was arrived at by watching a plausible one fail. The
//! failures were uniformly SILENT: rules that matched zero packets while the
//! service answered anyway, or blanket blocks that appeared to work because the
//! thing they broke was only used later. `iptables -L` looked correct in every
//! case. Packet counters were the only thing that told the truth, which is why
//! [`EgressPolicy::verify_commands`] exists at all.

use std::fmt;

/// Where the private network lives. CGNAT space, as used by Tailscale.
const PRIVATE_MESH: &str = "100.64.0.0/10";

/// RFC1918. Blocking these is what stops an agent reaching another Docker
/// network — the database and object store behind the surface it talks to.
const RFC1918: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];

/// An endpoint on the host that an agent is permitted to reach.
///
/// The distinction between these two variants is the single most expensive thing
/// in this file. It is invisible in `docker ps`, invisible in `iptables -L`, and
/// determines whether the allow rule matches anything at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Allowed {
    /// A port served by a process running ON THE HOST, bound to `addr`.
    ///
    /// The packet arrives at a local address unmodified, so this is ordinary
    /// INPUT traffic and a plain `--dport` matches.
    HostProcess { addr: String, port: u16 },

    /// A port PUBLISHED by a container, which Docker implements with DNAT.
    ///
    /// The rewrite happens in nat/PREROUTING, which runs BEFORE the filter
    /// chains — so by the time a filter rule sees the packet, both the
    /// destination address and port are the container's, and a rule written
    /// against the published port matches nothing. It fails silently: the
    /// service still answers (via a broader rule) while the counter sits at 0,
    /// so the lock reads as working.
    ///
    /// `container_port` is what the traffic is rewritten TO, and is recorded
    /// only so the generated rule can be explained.
    PublishedPort { addr: String, port: u16, container_port: u16 },
}

impl Allowed {
    pub fn port(&self) -> u16 {
        match self {
            Self::HostProcess { port, .. } | Self::PublishedPort { port, .. } => *port,
        }
    }
}

/// The egress policy for one agent network.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    /// The agent network's subnet, e.g. `172.20.0.0/16`.
    pub subnet: String,
    pub allow: Vec<Allowed>,
}

/// One iptables rule, as the chain it belongs in plus its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub chain: &'static str,
    /// True when the rule must be INSERTED at position 1 rather than appended.
    pub insert_at_top: bool,
    pub args: Vec<String>,
    /// Why this rule exists, for `hive doctor` output and for the next person.
    pub why: &'static str,
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let op = if self.insert_at_top { "-I" } else { "-A" };
        let pos = if self.insert_at_top { " 1" } else { "" };
        write!(f, "iptables {op} {}{pos} {}", self.chain, self.args.join(" "))
    }
}

impl EgressPolicy {
    /// The complete rule set, in the order it must be applied.
    ///
    /// Order is load-bearing twice over: allow rules must precede the INPUT
    /// drop, and the FORWARD drop must be inserted above rules this process
    /// does not own.
    pub fn rules(&self) -> Vec<Rule> {
        let s = &self.subnet;
        let mut rules = Vec::new();

        // 1. Allow the named endpoints. These must come before rule 2.
        for a in &self.allow {
            match a {
                Allowed::HostProcess { addr, port } => rules.push(Rule {
                    chain: "INPUT",
                    // Inserted, because rule 2 may already be installed from a
                    // previous run; an appended allow would sit below the drop
                    // and never be reached.
                    insert_at_top: true,
                    args: vec![
                        "-s".into(), s.clone(),
                        "-d".into(), addr.clone(),
                        "-p".into(), "tcp".into(),
                        "--dport".into(), port.to_string(),
                        "-j".into(), "ACCEPT".into(),
                    ],
                    why: "host process bound to a local address: plain --dport matches",
                }),

                Allowed::PublishedPort { addr, port, .. } => rules.push(Rule {
                    chain: "INPUT",
                    insert_at_top: true,
                    args: vec![
                        "-s".into(), s.clone(),
                        "-p".into(), "tcp".into(),
                        // --ctorigdst / --ctorigdstport match the destination as
                        // it was BEFORE DNAT, which is the only way to express
                        // "the published port" once the rewrite has happened.
                        "-m".into(), "conntrack".into(),
                        "--ctorigdst".into(), addr.clone(),
                        "--ctorigdstport".into(), port.to_string(),
                        // --ctdir ORIGINAL is NOT optional. Without it the match
                        // is direction-agnostic and also matches the REPLY
                        // direction of unrelated connections — which, combined
                        // with a DROP below, silently killed all container egress
                        // including api.anthropic.com. The agent simply stopped
                        // answering, with nothing in any log to connect it to a
                        // firewall change.
                        "--ctdir".into(), "ORIGINAL".into(),
                        "-j".into(), "ACCEPT".into(),
                    ],
                    why: "published port is DNAT'd before the filter chains: \
                          --dport would match nothing while the service still answers",
                }),
            }
        }

        // 2. Deny every other TCP port on the host.
        //
        // udp/53 is deliberately untouched: Docker's embedded resolver forwards
        // through the host, and dropping it breaks name resolution for every
        // outbound request in a way that looks like the internet is down.
        rules.push(Rule {
            chain: "INPUT",
            insert_at_top: false,
            args: vec!["-s".into(), s.clone(), "-p".into(), "tcp".into(), "-j".into(), "DROP".into()],
            why: "deny all other host ports; udp/53 left alone for Docker's resolver",
        });

        // 3. Deny the rest of the private mesh.
        rules.push(Rule {
            chain: "FORWARD",
            // MUST be inserted at the top. Docker and ufw both install their own
            // ACCEPT rules in FORWARD, so an APPENDED drop is never reached. This
            // was found by probing a peer node from inside an agent and getting a
            // 302 back — a rule that existed, read correctly, and did nothing.
            insert_at_top: true,
            args: vec![
                "-s".into(), s.clone(),
                "-d".into(), PRIVATE_MESH.into(),
                "-j".into(), "DROP".into(),
            ],
            why: "no lateral movement to mesh peers; inserted above Docker/ufw ACCEPTs",
        });

        // 4. Deny other Docker networks and private ranges generally.
        //
        // DOCKER-USER is the one chain Docker guarantees it will not rewrite.
        // Rules placed in FORWARD directly are liable to be reordered or removed
        // whenever the daemon reloads.
        for d in RFC1918 {
            rules.push(Rule {
                chain: "DOCKER-USER",
                insert_at_top: false,
                args: vec![
                    "-s".into(), s.clone(),
                    "-d".into(), (*d).into(),
                    "-j".into(), "DROP".into(),
                ],
                why: "no other Docker network: the surface's database, cache and object store",
            });
        }

        rules
    }

    /// Commands that report each rule's PACKET COUNTER.
    ///
    /// The reason this exists: every firewall bug found on this box presented as
    /// a rule that was present and correct-looking while matching zero packets.
    /// Listing rules proves only that they were installed. A counter that stays
    /// at zero while the thing it governs demonstrably works is the actual signal
    /// that a rule is not doing what it says.
    pub fn verify_commands(&self) -> Vec<String> {
        ["INPUT", "FORWARD", "DOCKER-USER"]
            .iter()
            .map(|c| format!("iptables -L {c} -v -n --line-numbers"))
            .collect()
    }
}

/// Options every agent network must be created with.
///
/// Returned as data rather than applied here so the Docker backend owns all I/O.
pub fn network_create_options() -> Vec<(&'static str, &'static str)> {
    vec![
        // THE ONLY THING THAT ISOLATES AGENTS FROM EACH OTHER.
        //
        // Two containers on the same bridge talk directly at layer 2. That
        // traffic traverses iptables only when br_netfilter is loaded — and on
        // the box this was built against it is not, and /proc/sys/net/bridge
        // does not exist at all. So NO rule in EgressPolicy can block
        // agent-to-agent traffic. Only refusing inter-container communication at
        // the bridge does.
        //
        // Verified by probing a peer container by RAW IP from inside an agent,
        // not by name — name resolution failing is not isolation, it is just DNS,
        // and testing by name reports success while the network is wide open.
        ("com.docker.network.bridge.enable_icc", "false"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with(allow: Allowed) -> EgressPolicy {
        EgressPolicy { subnet: "172.20.0.0/16".into(), allow: vec![allow] }
    }

    fn rendered(p: &EgressPolicy) -> Vec<String> {
        p.rules().iter().map(|r| r.to_string()).collect()
    }

    #[test]
    fn published_ports_match_on_the_pre_dnat_destination_not_dport() {
        // The original failure: `--dport 8000` against a container publishing
        // 8000->8080 matched 0 packets, while the port answered publicly. The
        // rule looked right in `iptables -L` and did nothing.
        let p = policy_with(Allowed::PublishedPort {
            addr: "100.64.0.1".into(),
            port: 8000,
            container_port: 8080,
        });
        let allow = &rendered(&p)[0];
        assert!(allow.contains("--ctorigdstport 8000"), "got: {allow}");
        assert!(!allow.contains("--dport"), "a DNAT'd port must not be matched with --dport: {allow}");
    }

    #[test]
    fn conntrack_allows_are_scoped_to_the_original_direction() {
        // Without --ctdir ORIGINAL the match also fires on the REPLY direction of
        // unrelated connections. Combined with the DROP below it, that took out
        // ALL container egress — the agent went silent and nothing logged why.
        let p = policy_with(Allowed::PublishedPort {
            addr: "100.64.0.1".into(),
            port: 443,
            container_port: 8080,
        });
        assert!(rendered(&p)[0].contains("--ctdir ORIGINAL"));
    }

    #[test]
    fn host_process_ports_use_plain_dport() {
        // The mirror case. A host process bound to a local address is NOT
        // DNAT'd, so conntrack matching here would be cargo cult — and would
        // obscure the distinction that matters.
        let p = policy_with(Allowed::HostProcess { addr: "100.64.0.1".into(), port: 443 });
        let allow = &rendered(&p)[0];
        assert!(allow.contains("--dport 443"), "got: {allow}");
        assert!(!allow.contains("conntrack"), "host-process ports need no conntrack: {allow}");
    }

    #[test]
    fn allow_rules_precede_the_input_drop() {
        // Ordering, not membership. An allow appended after the drop is present,
        // correct, and unreachable.
        let p = policy_with(Allowed::HostProcess { addr: "100.64.0.1".into(), port: 443 });
        let rules = p.rules();
        let drop_idx = rules
            .iter()
            .position(|r| r.chain == "INPUT" && r.args.contains(&"DROP".to_string()))
            .expect("INPUT drop must exist");
        let allow_idx = rules
            .iter()
            .position(|r| r.chain == "INPUT" && r.args.contains(&"ACCEPT".to_string()))
            .expect("INPUT allow must exist");
        assert!(allow_idx < drop_idx, "allow must precede drop");
        assert!(rules[allow_idx].insert_at_top, "allow must be inserted, not appended");
    }

    #[test]
    fn the_mesh_drop_is_inserted_above_rules_we_do_not_own() {
        // Appended, this sat below Docker's and ufw's own ACCEPTs and never
        // matched: an agent could still reach a peer node, which answered 302.
        let p = policy_with(Allowed::HostProcess { addr: "100.64.0.1".into(), port: 443 });
        let fwd = p.rules().into_iter().find(|r| r.chain == "FORWARD").unwrap();
        assert!(fwd.insert_at_top, "FORWARD drop must be inserted at position 1");
        assert!(fwd.args.contains(&PRIVATE_MESH.to_string()));
    }

    #[test]
    fn other_docker_networks_are_blocked_in_the_chain_docker_respects() {
        // DOCKER-USER, not FORWARD: Docker rewrites FORWARD on daemon reload and
        // the rule quietly disappears.
        let p = policy_with(Allowed::HostProcess { addr: "100.64.0.1".into(), port: 443 });
        let rules = p.rules();
        for cidr in RFC1918 {
            assert!(
                rules.iter().any(|r| r.chain == "DOCKER-USER" && r.args.contains(&cidr.to_string())),
                "{cidr} not blocked in DOCKER-USER"
            );
        }
    }

    #[test]
    fn dns_is_never_dropped() {
        // Dropping udp/53 breaks Docker's embedded resolver, and the symptom is
        // "every outbound request fails" — which reads as the network being down
        // rather than as a firewall rule.
        let p = policy_with(Allowed::HostProcess { addr: "100.64.0.1".into(), port: 443 });
        for r in p.rules() {
            if r.args.contains(&"DROP".to_string()) {
                assert!(!r.args.contains(&"udp".to_string()), "policy drops UDP: {r}");
            }
        }
    }

    #[test]
    fn agent_networks_always_disable_inter_container_communication() {
        // The one isolation control that works when br_netfilter is absent. If
        // this ever becomes conditional, agents can reach each other by raw IP
        // and every rule in this file still passes.
        let opts = network_create_options();
        assert_eq!(
            opts.iter()
                .find(|(k, _)| *k == "com.docker.network.bridge.enable_icc")
                .map(|(_, v)| *v),
            Some("false")
        );
    }

    #[test]
    fn verification_reports_counters_because_presence_proves_nothing() {
        // -v is the entire point: every firewall bug here was a rule that was
        // present and matched zero packets.
        let p = EgressPolicy { subnet: "172.20.0.0/16".into(), allow: vec![] };
        for cmd in p.verify_commands() {
            assert!(cmd.contains(" -v"), "verification must show packet counters: {cmd}");
        }
    }
}
