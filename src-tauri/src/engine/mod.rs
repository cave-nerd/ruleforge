use serde::{Deserialize, Serialize};

use crate::nmap::{PortResult, ScanResult};
use crate::opnsense::rules::{FirewallRule, RuleAction, RuleDirection};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RiskProfile {
    Strict,
    Balanced,
    Permissive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub rule: FirewallRule,
    pub rationale: String,
    pub severity: RiskSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendationSet {
    pub profile: RiskProfile,
    pub recommendations: Vec<Recommendation>,
    pub summary: String,
}

// ── Dangerous service definitions ───────────────────────────────────────────

struct ServicePolicy {
    name: &'static str,
    ports: &'static [u16],
    reason: &'static str,
    severity: RiskSeverity,
}

const ALWAYS_BLOCK: &[ServicePolicy] = &[
    ServicePolicy {
        name: "Telnet",
        ports: &[23],
        reason: "Plaintext credential transmission; replace with SSH",
        severity: RiskSeverity::Critical,
    },
    ServicePolicy {
        name: "SMBv1 / NetBIOS",
        ports: &[139, 445],
        reason: "Exploitable by EternalBlue; block inbound from untrusted networks",
        severity: RiskSeverity::Critical,
    },
    ServicePolicy {
        name: "RDP",
        ports: &[3389],
        reason: "Frequent brute-force target; restrict to trusted source IPs",
        severity: RiskSeverity::High,
    },
    ServicePolicy {
        name: "TFTP",
        ports: &[69],
        reason: "Unauthenticated file transfer; block unless required for PXE boot",
        severity: RiskSeverity::High,
    },
    ServicePolicy {
        name: "SNMP v1/v2",
        ports: &[161, 162],
        reason: "Plaintext community strings expose device info",
        severity: RiskSeverity::High,
    },
    ServicePolicy {
        name: "rsh/rlogin/rexec",
        ports: &[512, 513, 514],
        reason: "Legacy trust-based auth; no encryption",
        severity: RiskSeverity::Critical,
    },
    ServicePolicy {
        name: "FTP",
        ports: &[20, 21],
        reason: "Plaintext credentials; use SFTP or FTPS instead",
        severity: RiskSeverity::High,
    },
    ServicePolicy {
        name: "VNC",
        ports: &[5900, 5901],
        reason: "Often exposed with weak or no authentication",
        severity: RiskSeverity::High,
    },
    ServicePolicy {
        name: "Redis",
        ports: &[6379],
        reason: "No auth by default; should never be exposed publicly",
        severity: RiskSeverity::Critical,
    },
    ServicePolicy {
        name: "MongoDB",
        ports: &[27017],
        reason: "Default configs allow unauthenticated access",
        severity: RiskSeverity::Critical,
    },
    ServicePolicy {
        name: "Elasticsearch",
        ports: &[9200, 9300],
        reason: "Unauthenticated by default; exposes data",
        severity: RiskSeverity::Critical,
    },
    ServicePolicy {
        name: "MySQL / MariaDB",
        ports: &[3306],
        reason: "Database should not be exposed publicly",
        severity: RiskSeverity::High,
    },
    ServicePolicy {
        name: "PostgreSQL",
        ports: &[5432],
        reason: "Database should not be exposed publicly",
        severity: RiskSeverity::High,
    },
    ServicePolicy {
        name: "Docker API",
        ports: &[2375, 2376],
        reason: "Unauthenticated Docker daemon allows full host compromise",
        severity: RiskSeverity::Critical,
    },
    ServicePolicy {
        name: "Kubernetes API",
        ports: &[6443, 8080],
        reason: "Exposed k8s API allows cluster takeover",
        severity: RiskSeverity::Critical,
    },
];

// Ports allowed under Balanced (CIS Level 1) profile
const BALANCED_ALLOW_PORTS: &[u16] = &[
    22,   // SSH
    53,   // DNS
    80,   // HTTP
    123,  // NTP
    443,  // HTTPS
    587,  // SMTP submission
    993,  // IMAPS
    8080, // Alt HTTP (conditional)
    8443, // Alt HTTPS
];

// ── Engine ───────────────────────────────────────────────────────────────────

pub fn generate(scan: &ScanResult, profile: RiskProfile, interface: &str) -> RecommendationSet {
    let mut recs: Vec<Recommendation> = Vec::new();

    for host in &scan.hosts {
        for port in &host.ports {
            if port.state != "open" {
                continue;
            }

            match profile {
                RiskProfile::Strict => strict_rules(port, &host.ip, interface, &mut recs),
                RiskProfile::Balanced => balanced_rules(port, &host.ip, interface, &mut recs),
                RiskProfile::Permissive => permissive_rules(port, &host.ip, interface, &mut recs),
            }
        }
    }

    // Deduplicate by port+action — use a HashSet so non-consecutive
    // duplicates are caught (dedup_by only removes adjacent matches).
    {
        let mut seen = std::collections::HashSet::new();
        recs.retain(|r| {
            let key = (r.rule.destination_port.clone(), r.rule.action.clone());
            seen.insert(key)
        });
    }

    let summary = build_summary(&recs, &profile);

    RecommendationSet {
        profile,
        recommendations: recs,
        summary,
    }
}

fn strict_rules(
    port: &PortResult,
    _dst_ip: &str,
    interface: &str,
    recs: &mut Vec<Recommendation>,
) {
    // Strict: block everything unless conf == 10 AND port is in a narrow allowlist
    let strict_allow: &[u16] = &[22, 443];

    if port.conf == 10 && strict_allow.contains(&port.port) {
        recs.push(Recommendation {
            rule: make_rule(
                RuleAction::Pass,
                interface,
                port,
                &format!(
                    "STRICT — Allow {} (high confidence service)",
                    port.service_name
                ),
                false,
            ),
            rationale: format!(
                "Port {} identified as {} with maximum confidence (10); permitted under strict zero-trust profile.",
                port.port, port.service_name
            ),
            severity: RiskSeverity::Info,
        });
    } else {
        let (reason, severity) = classify_port(port);
        recs.push(Recommendation {
            rule: make_rule(
                RuleAction::Block,
                interface,
                port,
                &format!("STRICT — Block {} ({})", port.port, port.service_name),
                false,
            ),
            rationale: format!(
                "Strict zero-trust profile: block all unless conf=10 and explicitly whitelisted. {reason}"
            ),
            severity,
        });
    }
}

fn balanced_rules(
    port: &PortResult,
    _dst_ip: &str,
    interface: &str,
    recs: &mut Vec<Recommendation>,
) {
    // Block explicitly dangerous services regardless of confidence
    if let Some(policy) = find_dangerous_policy(port.port) {
        recs.push(Recommendation {
            rule: make_rule(
                RuleAction::Block,
                interface,
                port,
                &format!("BALANCED — Block {} ({})", policy.name, port.port),
                false,
            ),
            rationale: format!("CIS Level 1: {}.", policy.reason),
            severity: policy.severity.clone(),
        });
        return;
    }

    if BALANCED_ALLOW_PORTS.contains(&port.port) {
        recs.push(Recommendation {
            rule: make_rule(
                RuleAction::Pass,
                interface,
                port,
                &format!("BALANCED — Allow {} ({})", port.service_name, port.port),
                true,
            ),
            rationale: format!(
                "CIS Level 1: port {} ({}) is in the standard allow-list for internet-facing services.",
                port.port, port.service_name
            ),
            severity: RiskSeverity::Info,
        });
    } else {
        let (reason, severity) = classify_port(port);
        recs.push(Recommendation {
            rule: make_rule(
                RuleAction::Block,
                interface,
                port,
                &format!("BALANCED — Block non-standard {} ({})", port.port, port.service_name),
                true,
            ),
            rationale: format!("Port is not in the CIS Level 1 standard allow-list. {reason}"),
            severity,
        });
    }
}

fn permissive_rules(
    port: &PortResult,
    _dst_ip: &str,
    interface: &str,
    recs: &mut Vec<Recommendation>,
) {
    // Permissive: log-only, no blocking. Alert on dangerous services.
    let severity = if find_dangerous_policy(port.port).is_some() {
        RiskSeverity::High
    } else {
        RiskSeverity::Info
    };

    let rationale = if let Some(policy) = find_dangerous_policy(port.port) {
        format!(
            "ALERT: dangerous service detected on port {} ({}). {}",
            port.port, policy.name, policy.reason
        )
    } else {
        format!(
            "Permissive audit mode: logging traffic on port {} ({}) for discovery.",
            port.port, port.service_name
        )
    };

    recs.push(Recommendation {
        rule: FirewallRule {
            uuid: None,
            action: RuleAction::Pass,
            direction: RuleDirection::In,
            interface: interface.to_string(),
            protocol: port.protocol.to_uppercase(),
            source_net: "any".to_string(),
            destination_net: "any".to_string(),
            destination_port: port.port.to_string(),
            description: format!(
                "PERMISSIVE — Log {} ({}) | conf={}",
                port.service_name, port.port, port.conf
            ),
            enabled: true,
            log: true,
        },
        rationale,
        severity,
    });
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn make_rule(
    action: RuleAction,
    interface: &str,
    port: &PortResult,
    description: &str,
    log: bool,
) -> FirewallRule {
    FirewallRule {
        uuid: None,
        action,
        direction: RuleDirection::In,
        interface: interface.to_string(),
        protocol: port.protocol.to_uppercase(),
        source_net: "any".to_string(),
        destination_net: "any".to_string(),
        destination_port: port.port.to_string(),
        description: description.to_string(),
        enabled: true,
        log,
    }
}

fn find_dangerous_policy(port: u16) -> Option<&'static ServicePolicy> {
    ALWAYS_BLOCK
        .iter()
        .find(|p| p.ports.contains(&port))
}

fn classify_port(port: &PortResult) -> (String, RiskSeverity) {
    if port.conf < 3 {
        (
            format!(
                "Service confidence is very low ({}); treat as unverified.",
                port.conf
            ),
            RiskSeverity::Medium,
        )
    } else if port.conf < 7 {
        (
            format!(
                "Service confidence moderate ({}); {}.",
                port.conf, port.service_name
            ),
            RiskSeverity::Low,
        )
    } else {
        (
            format!(
                "High confidence service {} on port {}.",
                port.service_name, port.port
            ),
            RiskSeverity::Info,
        )
    }
}

fn build_summary(recs: &[Recommendation], profile: &RiskProfile) -> String {
    let blocks = recs
        .iter()
        .filter(|r| r.rule.action == RuleAction::Block)
        .count();
    let passes = recs
        .iter()
        .filter(|r| r.rule.action == RuleAction::Pass)
        .count();
    let critical = recs
        .iter()
        .filter(|r| matches!(r.severity, RiskSeverity::Critical))
        .count();

    format!(
        "{profile:?} profile: {total} rules proposed — {passes} allow, {blocks} block, {critical} critical findings.",
        total = recs.len()
    )
}
