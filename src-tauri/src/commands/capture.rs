use tauri_plugin_shell::ShellExt;

use crate::capture::{parse_capture_file, CaptureResult};
use crate::engine::{Recommendation, RecommendationSet, RiskProfile, RiskSeverity};
use crate::opnsense::rules::{FirewallRule, RuleAction, RuleDirection};

// ── Path validation ───────────────────────────────────────────────────────────

fn validate_capture_path(path: &str) -> Result<(), String> {
    // Reject NUL bytes
    if path.contains('\0') {
        return Err("File path contains invalid characters.".into());
    }
    // Reject path traversal sequences
    if path.contains("..") {
        return Err("File path must not contain '..'".into());
    }
    // Reject shell metacharacters (defense-in-depth; Tauri passes args as a
    // vec rather than through a shell, but we validate here too).
    let has_metachar = path.chars().any(|c| {
        matches!(c, ';' | '|' | '&' | '$' | '`' | '\'' | '"' | '>' | '<' | '(' | ')' | '!' | '\n' | '\r')
    });
    if has_metachar {
        return Err("File path contains disallowed characters.".into());
    }
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    match ext.as_str() {
        "pcap" | "pcapng" | "cap" | "npcapng" | "json" => Ok(()),
        _ => Err(format!(
            "Unsupported extension '.{}'. Accepted: .pcap, .pcapng, .cap, .json",
            ext
        )),
    }
}

// ── Commands ──────────────────────────────────────────────────────────────────

/// Parse a capture file (pcap / pcapng / tshark JSON) selected by the user.
#[tauri::command]
pub fn parse_capture(file_path: String) -> Result<CaptureResult, String> {
    validate_capture_path(&file_path)?;
    parse_capture_file(&file_path).map_err(|e| e.to_string())
}

/// Invoke tshark on a pcap/pcapng file and parse its JSON output directly.
/// Requires tshark to be installed on PATH. This gives richer layer-7
/// protocol detail than the pure-Rust packet parser.
#[tauri::command]
pub async fn run_tshark_on_capture(
    app: tauri::AppHandle,
    file_path: String,
) -> Result<CaptureResult, String> {
    validate_capture_path(&file_path)?;

    let shell = app.shell();
    let output = shell
        .command("tshark")
        .args(&[
            "-r", &file_path,
            "-T", "json",
            "-e", "frame.len",
            "-e", "frame.protocols",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ipv6.src",
            "-e", "ipv6.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.srcport",
            "-e", "udp.dstport",
        ])
        .output()
        .await
        .map_err(|e| {
            format!(
                "Failed to invoke tshark: {}. Ensure tshark is installed and on PATH.",
                e
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("tshark exited with error: {}", stderr));
    }

    // Write stdout to a temp file and parse it as tshark JSON.
    // Use a UUID v4 (cryptographically random) for the filename so it cannot
    // be predicted or guessed. O_EXCL prevents symlink attacks.
    let tmp_path = std::env::temp_dir()
        .join(format!("ruleforge_tshark_{}.json", uuid::Uuid::new_v4()));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true) // O_EXCL — fails if the path already exists
        .open(&tmp_path)
        .and_then(|mut f| {
            use std::io::Write;
            f.write_all(&output.stdout)
        })
        .map_err(|e| format!("Failed to write tshark output: {}", e))?;
    let tmp_path = tmp_path.to_string_lossy().into_owned();

    let result = crate::capture::parse_tshark_json(&tmp_path)
        .map_err(|e| format!("Failed to parse tshark output: {}", e));

    // Clean up temp file regardless of parse outcome
    let _ = std::fs::remove_file(&tmp_path);

    let mut r = result?;
    // Override the source filename to show the original capture file
    r.source_file = std::path::Path::new(&file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&file_path)
        .to_string();
    Ok(r)
}

// ── Rule generation from capture data ────────────────────────────────────────

fn port_service_name(port: u16) -> &'static str {
    match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        69 => "TFTP",
        80 => "HTTP",
        110 => "POP3",
        123 => "NTP",
        139 => "NetBIOS",
        143 => "IMAP",
        161 | 162 => "SNMP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        512 | 513 | 514 => "rsh/rlogin",
        587 => "SMTP-submission",
        636 => "LDAPS",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "MSSQL",
        1521 => "Oracle-DB",
        2375 | 2376 => "Docker-API",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900 | 5901 => "VNC",
        6379 => "Redis",
        6443 => "k8s-API",
        8080 => "HTTP-alt",
        8443 => "HTTPS-alt",
        9200 | 9300 => "Elasticsearch",
        27017 => "MongoDB",
        _ => "Unknown",
    }
}

// Ports that must be blocked regardless of profile (critical/high risk services)
const ALWAYS_BLOCK: &[u16] = &[
    23, 20, 21, 69, 139, 445, 512, 513, 514,
    161, 162, 3389, 5900, 5901, 6379, 27017,
    9200, 9300, 2375, 2376, 6443, 1433, 1521,
    3306, 5432,
];

// Ports allowed by default under the balanced (CIS L1) profile
const BALANCED_ALLOW: &[u16] = &[22, 53, 80, 123, 443, 587, 993, 8080, 8443];

fn block_severity(port: u16) -> RiskSeverity {
    match port {
        23 | 6379 | 27017 | 9200 | 9300 | 2375 | 2376
        | 139 | 445 | 512 | 513 | 514 | 6443 => RiskSeverity::Critical,
        _ => RiskSeverity::High,
    }
}

fn make_fw_rule(
    action: RuleAction,
    iface: &str,
    protocol: &str,
    src: &str,
    dst: &str,
    port: &str,
    description: String,
    log: bool,
) -> FirewallRule {
    FirewallRule {
        uuid: None,
        action,
        direction: RuleDirection::In,
        interface: iface.to_string(),
        protocol: protocol.to_string(),
        source_net: src.to_string(),
        destination_net: dst.to_string(),
        destination_port: port.to_string(),
        description,
        enabled: true,
        log,
    }
}

// ── Tag relationship engine ───────────────────────────────────────────────────

/// Returns `Some(true)` if the tag relationship explicitly permits the
/// connection, `Some(false)` if it explicitly blocks it, or `None` if
/// there is no tag-based opinion (fall back to port-based rules).
fn tag_relationship(from_tags: &[String], to_tags: &[String]) -> Option<bool> {
    let src = |t: &str| from_tags.iter().any(|x| x == t);
    let dst = |t: &str| to_tags.iter().any(|x| x == t);

    // Admin / monitor can reach everything (including all infrastructure)
    if src("admin") || src("monitor") {
        return Some(true);
    }

    // IoT must be maximally isolated
    if src("iot") {
        if dst("frontend") || dst("dmz") || dst("vpn") {
            return Some(true); // only permitted egress for IoT
        }
        // Block IoT from all other tiers
        if dst("backend") || dst("database") || dst("cache") || dst("internal")
            || dst("nas") || dst("container-host") || dst("router")
            || dst("firewall") || dst("switch") || dst("access-point")
        {
            return Some(false);
        }
    }

    // External must not reach trusted infrastructure or internal tiers
    if src("external") {
        if dst("frontend") || dst("dmz") || dst("vpn") {
            return Some(true); // valid entry points for external hosts
        }
        if dst("backend") || dst("database") || dst("cache") || dst("internal")
            || dst("nas") || dst("container-host") || dst("router")
            || dst("firewall") || dst("switch")
        {
            return Some(false);
        }
    }

    // Client: may only reach public-facing and VPN gateway
    if src("client") {
        if dst("frontend") || dst("dmz") || dst("vpn") || dst("access-point") {
            return Some(true);
        }
        if dst("backend") || dst("database") || dst("cache") || dst("internal")
            || dst("nas") || dst("container-host") || dst("router")
            || dst("firewall") || dst("switch")
        {
            return Some(false);
        }
    }

    // Frontend tier: proxies to backend, cache, and container workloads
    if src("frontend") {
        if dst("backend") || dst("cache") || dst("database") || dst("container-host") {
            return Some(true);
        }
    }

    // Backend tier: data stores and container workloads
    if src("backend") {
        if dst("database") || dst("cache") || dst("container-host") || dst("nas") {
            return Some(true);
        }
    }

    // Container hosts: may reach databases, caches, and NAS (typical workloads)
    if src("container-host") {
        if dst("database") || dst("cache") || dst("nas") {
            return Some(true);
        }
        if dst("external") || dst("iot") {
            return Some(false);
        }
    }

    // VPN: authenticated remote users route to internal / NAS / container-host
    if src("vpn") {
        if dst("internal") || dst("nas") || dst("container-host") || dst("backend") {
            return Some(true);
        }
        if dst("external") || dst("iot") {
            return Some(false);
        }
    }

    // Internal ↔ internal / NAS / container-host (trusted east-west)
    if src("internal") {
        if dst("internal") || dst("nas") || dst("container-host") {
            return Some(true);
        }
        if dst("external") || dst("iot") {
            return Some(false);
        }
    }

    // DMZ hosts: may only reach frontend and internet (block internal tiers)
    if src("dmz") {
        if dst("backend") || dst("database") || dst("cache") || dst("internal")
            || dst("nas") || dst("container-host")
        {
            return Some(false);
        }
    }

    // Infrastructure (router/firewall/switch/AP) management is handled by
    // admin/monitor above; all other traffic is left to port-based rules.
    None // no tag-defined relationship
}

fn tag_relationship_rationale(from_tags: &[String], to_tags: &[String], allowed: bool) -> String {
    let src_label = if from_tags.is_empty() { "untagged".to_string() } else { from_tags.join("+") };
    let dst_label = if to_tags.is_empty() { "untagged".to_string() } else { to_tags.join("+") };
    if allowed {
        format!("Tag policy: {} → {} connection is expected and permitted.", src_label, dst_label)
    } else {
        format!(
            "Tag policy: {} hosts must NOT reach {} hosts directly. \
             This rule enforces network segmentation.",
            src_label, dst_label
        )
    }
}

/// Analyse an ingested packet capture and generate proposed firewall rules.
///
/// When `host_tags` is provided the engine generates precise inter-host
/// allow/block rules based on role relationships (frontend, backend,
/// database, client, etc.) in addition to the port-based rules.
#[tauri::command]
pub fn generate_recommendations_from_capture(
    capture: CaptureResult,
    profile: String,
    interface: String,
    host_tags: std::collections::HashMap<String, Vec<String>>,
) -> Result<RecommendationSet, String> {
    let iface = if interface.is_empty() { "wan".to_string() } else { interface };
    let profile_enum = match profile.as_str() {
        "strict" => RiskProfile::Strict,
        "permissive" => RiskProfile::Permissive,
        _ => RiskProfile::Balanced,
    };

    let mut recs: Vec<Recommendation> = Vec::new();
    let mut seen: std::collections::HashSet<(String, u16)> = std::collections::HashSet::new();

    // ── Per-host listening-port rules ─────────────────────────────────────────
    for host in &capture.hosts {
        for &port in &host.listening_ports {
            // Deduplicate: balanced generates "any" destination so one rule per port is enough
            let key = (host.ip.clone(), port);
            if !seen.insert(key) {
                continue;
            }

            let svc = port_service_name(port);
            let dangerous = ALWAYS_BLOCK.contains(&port);

            let rec = match profile_enum {
                RiskProfile::Strict => {
                    if [22u16, 443u16].contains(&port) {
                        Recommendation {
                            rule: make_fw_rule(
                                RuleAction::Pass, &iface, "TCP", "any", &host.ip,
                                &port.to_string(),
                                format!("STRICT — Allow {} ({}) → {}", svc, port, host.ip),
                                false,
                            ),
                            rationale: format!(
                                "Port {} ({}) is in the strict zero-trust allowlist; observed on {}.",
                                port, svc, host.ip
                            ),
                            severity: RiskSeverity::Info,
                        }
                    } else {
                        Recommendation {
                            rule: make_fw_rule(
                                RuleAction::Block, &iface, "TCP", "any", &host.ip,
                                &port.to_string(),
                                format!("STRICT — Block {} ({}) → {}", svc, port, host.ip),
                                false,
                            ),
                            rationale: format!(
                                "Strict zero-trust: block all ports not explicitly whitelisted. \
                                 Port {} ({}) observed on {}.",
                                port, svc, host.ip
                            ),
                            severity: if dangerous { block_severity(port) } else { RiskSeverity::Medium },
                        }
                    }
                }

                RiskProfile::Balanced => {
                    if dangerous {
                        Recommendation {
                            rule: make_fw_rule(
                                RuleAction::Block, &iface, "TCP", "any", "any",
                                &port.to_string(),
                                format!("BALANCED — Block {} ({}) [dangerous]", svc, port),
                                false,
                            ),
                            rationale: format!(
                                "Live traffic to {} port {} was captured. \
                                 This service is flagged as high-risk and should be blocked network-wide.",
                                svc, port
                            ),
                            severity: block_severity(port),
                        }
                    } else if BALANCED_ALLOW.contains(&port) {
                        Recommendation {
                            rule: make_fw_rule(
                                RuleAction::Pass, &iface, "TCP", "any", "any",
                                &port.to_string(),
                                format!("BALANCED — Allow {} ({})", svc, port),
                                true,
                            ),
                            rationale: format!(
                                "Port {} ({}) is in the CIS Level 1 standard allow-list \
                                 and was observed active in the capture.",
                                port, svc
                            ),
                            severity: RiskSeverity::Info,
                        }
                    } else {
                        Recommendation {
                            rule: make_fw_rule(
                                RuleAction::Block, &iface, "TCP", "any", &host.ip,
                                &port.to_string(),
                                format!("BALANCED — Block non-standard {} ({}) → {}", svc, port, host.ip),
                                true,
                            ),
                            rationale: format!(
                                "Port {} ({}) on {} is not in the CIS Level 1 standard allow-list \
                                 and was observed in capture.",
                                port, svc, host.ip
                            ),
                            severity: RiskSeverity::Medium,
                        }
                    }
                }

                RiskProfile::Permissive => Recommendation {
                    rule: make_fw_rule(
                        RuleAction::Pass, &iface, "TCP", "any", &host.ip,
                        &port.to_string(),
                        format!("PERMISSIVE — Log {} ({}) → {}", svc, port, host.ip),
                        true,
                    ),
                    rationale: if dangerous {
                        format!(
                            "ALERT: dangerous service {} detected on port {} of {}. \
                             Consider upgrading to Balanced or Strict profile to block it.",
                            svc, port, host.ip
                        )
                    } else {
                        format!(
                            "Permissive audit: logging traffic to {} ({}) on {} for discovery.",
                            svc, port, host.ip
                        )
                    },
                    severity: if dangerous { block_severity(port) } else { RiskSeverity::Info },
                },
            };

            recs.push(rec);
        }
    }

    // ── Tag-based inter-host rules ────────────────────────────────────────────
    // For every ordered pair of hosts where at least the source has tags,
    // generate explicit allow or block rules based on role relationships.
    if !host_tags.is_empty() {
        let empty: Vec<String> = Vec::new();
        for src_host in &capture.hosts {
            let src_tags = host_tags.get(&src_host.ip).unwrap_or(&empty);
            if src_tags.is_empty() {
                continue;
            }
            for dst_host in &capture.hosts {
                if src_host.ip == dst_host.ip {
                    continue;
                }
                let dst_tags = host_tags.get(&dst_host.ip).unwrap_or(&empty);

                match tag_relationship(src_tags, dst_tags) {
                    Some(true) => {
                        // Allow src → dst on each of dst's observed listening ports
                        let ports: Vec<u16> = if dst_host.listening_ports.is_empty() {
                            vec![] // no port filter if we don't know the ports
                        } else {
                            dst_host.listening_ports.clone()
                        };

                        if ports.is_empty() {
                            recs.push(Recommendation {
                                rule: make_fw_rule(
                                    RuleAction::Pass, &iface, "TCP",
                                    &src_host.ip, &dst_host.ip, "any",
                                    format!(
                                        "TAG — Allow {} → {} ({}→{})",
                                        src_host.ip, dst_host.ip,
                                        src_tags.join("+"), dst_tags.join("+")
                                    ),
                                    true,
                                ),
                                rationale: tag_relationship_rationale(src_tags, dst_tags, true),
                                severity: RiskSeverity::Info,
                            });
                        } else {
                            for port in &ports {
                                let svc = port_service_name(*port);
                                recs.push(Recommendation {
                                    rule: make_fw_rule(
                                        RuleAction::Pass, &iface, "TCP",
                                        &src_host.ip, &dst_host.ip, &port.to_string(),
                                        format!(
                                            "TAG — Allow {} → {}:{} {} ({}→{})",
                                            src_host.ip, dst_host.ip, port, svc,
                                            src_tags.join("+"), dst_tags.join("+")
                                        ),
                                        true,
                                    ),
                                    rationale: tag_relationship_rationale(src_tags, dst_tags, true),
                                    severity: RiskSeverity::Info,
                                });
                            }
                        }
                    }
                    Some(false) => {
                        // Block src → dst entirely
                        recs.push(Recommendation {
                            rule: make_fw_rule(
                                RuleAction::Block, &iface, "any",
                                &src_host.ip, &dst_host.ip, "any",
                                format!(
                                    "TAG — Block {} → {} ({}→{})",
                                    src_host.ip, dst_host.ip,
                                    src_tags.join("+"), dst_tags.join("+")
                                ),
                                true,
                            ),
                            rationale: tag_relationship_rationale(src_tags, dst_tags, false),
                            severity: if dst_tags.iter().any(|t| matches!(t.as_str(), "database" | "cache" | "internal")) {
                                RiskSeverity::High
                            } else {
                                RiskSeverity::Medium
                            },
                        });
                    }
                    None => {} // no tag opinion; port-based rules apply
                }
            }
        }
    }

    // ── Scanner / flood findings (no specific port → block the source IP) ─────
    for finding in &capture.risk_findings {
        if finding.port.is_some() {
            continue; // already covered by per-port loop
        }
        if let Some(src_ip) = &finding.src_ip {
            let severity = finding.severity.clone();
            let action = if matches!(profile_enum, RiskProfile::Permissive) {
                RuleAction::Pass
            } else {
                RuleAction::Block
            };
            recs.push(Recommendation {
                rule: make_fw_rule(
                    action, &iface, "any", src_ip, "any", "any",
                    format!("Block suspicious source {}", src_ip),
                    true,
                ),
                rationale: finding.description.clone(),
                severity,
            });
        }
    }

    let blocks = recs.iter().filter(|r| r.rule.action == RuleAction::Block).count();
    let passes = recs.iter().filter(|r| r.rule.action == RuleAction::Pass).count();
    let critical = recs.iter().filter(|r| matches!(r.severity, RiskSeverity::Critical)).count();
    let summary = format!(
        "{} profile (from capture '{}') — {} rules: {} allow, {} block, {} critical. \
         {} hosts, {} risk findings analysed.",
        profile, capture.source_file, recs.len(), passes, blocks, critical,
        capture.hosts.len(), capture.risk_findings.len()
    );

    Ok(RecommendationSet {
        profile: profile_enum,
        recommendations: recs,
        summary,
    })
}
