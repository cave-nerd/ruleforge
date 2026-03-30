use std::collections::HashMap;

use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::{Block, PcapNgReader};
use serde::{Deserialize, Serialize};

use crate::engine::RiskSeverity;

const MAX_PACKETS: usize = 100_000;

// ── Output types (serialized to frontend) ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CaptureResult {
    pub source_file: String,
    pub format: CaptureFormat,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub hosts: Vec<CaptureHost>,
    pub conversations: Vec<Conversation>,
    pub protocol_counts: Vec<ProtocolCount>,
    pub risk_findings: Vec<CaptureFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CaptureFormat {
    #[default]
    Pcap,
    Pcapng,
    TsharkJson,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureHost {
    pub ip: String,
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub packets_recv: u64,
    pub bytes_recv: u64,
    /// Unique destination ports this host received traffic on
    pub listening_ports: Vec<u16>,
    /// Unique protocols observed
    pub protocols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub dst_port: Option<u16>,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCount {
    pub protocol: String,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureFinding {
    pub severity: RiskSeverity,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub port: Option<u16>,
    pub description: String,
}

// ── Internal accumulation types ───────────────────────────────────────────────

#[derive(Debug, Default)]
struct HostStats {
    packets_sent: u64,
    bytes_sent: u64,
    packets_recv: u64,
    bytes_recv: u64,
    listening_ports: std::collections::HashSet<u16>,
    protocols: std::collections::HashSet<String>,
}

#[derive(Debug, Hash, PartialEq, Eq)]
struct ConvKey {
    src_ip: String,
    dst_ip: String,
    protocol: String,
    dst_port: Option<u16>,
}

#[derive(Debug, Default)]
struct ConvStats {
    packets: u64,
    bytes: u64,
}

// ── Packet record extracted from any format ───────────────────────────────────

struct PacketInfo {
    src_ip: String,
    dst_ip: String,
    protocol: String,
    dst_port: Option<u16>,
    length: u64,
}

// ── Aggregation ───────────────────────────────────────────────────────────────

fn build_result(
    source_file: String,
    format: CaptureFormat,
    packets: Vec<PacketInfo>,
    total_bytes: u64,
) -> CaptureResult {
    let total_packets = packets.len() as u64;

    let mut host_map: HashMap<String, HostStats> = HashMap::new();
    let mut conv_map: HashMap<ConvKey, ConvStats> = HashMap::new();
    let mut proto_map: HashMap<String, (u64, u64)> = HashMap::new(); // (packets, bytes)

    for pkt in &packets {
        // Host stats
        let src_stats = host_map.entry(pkt.src_ip.clone()).or_default();
        src_stats.packets_sent += 1;
        src_stats.bytes_sent += pkt.length;
        src_stats.protocols.insert(pkt.protocol.clone());

        let dst_stats = host_map.entry(pkt.dst_ip.clone()).or_default();
        dst_stats.packets_recv += 1;
        dst_stats.bytes_recv += pkt.length;
        dst_stats.protocols.insert(pkt.protocol.clone());
        if let Some(port) = pkt.dst_port {
            dst_stats.listening_ports.insert(port);
        }

        // Conversation stats
        let key = ConvKey {
            src_ip: pkt.src_ip.clone(),
            dst_ip: pkt.dst_ip.clone(),
            protocol: pkt.protocol.clone(),
            dst_port: pkt.dst_port,
        };
        let conv = conv_map.entry(key).or_default();
        conv.packets += 1;
        conv.bytes += pkt.length;

        // Protocol stats
        let pe = proto_map.entry(pkt.protocol.clone()).or_default();
        pe.0 += 1;
        pe.1 += pkt.length;
    }

    let mut hosts: Vec<CaptureHost> = host_map
        .into_iter()
        .map(|(ip, s)| {
            let mut ports: Vec<u16> = s.listening_ports.into_iter().collect();
            ports.sort();
            let mut protos: Vec<String> = s.protocols.into_iter().collect();
            protos.sort();
            CaptureHost {
                ip,
                packets_sent: s.packets_sent,
                bytes_sent: s.bytes_sent,
                packets_recv: s.packets_recv,
                bytes_recv: s.bytes_recv,
                listening_ports: ports,
                protocols: protos,
            }
        })
        .collect();
    hosts.sort_by(|a, b| {
        (b.packets_sent + b.packets_recv).cmp(&(a.packets_sent + a.packets_recv))
    });

    let mut conversations: Vec<Conversation> = conv_map
        .into_iter()
        .map(|(k, s)| Conversation {
            src_ip: k.src_ip,
            dst_ip: k.dst_ip,
            protocol: k.protocol,
            dst_port: k.dst_port,
            packets: s.packets,
            bytes: s.bytes,
        })
        .collect();
    conversations.sort_by(|a, b| b.packets.cmp(&a.packets));
    conversations.truncate(500); // top 500 conversations in UI

    let mut protocol_counts: Vec<ProtocolCount> = proto_map
        .into_iter()
        .map(|(protocol, (p, b))| ProtocolCount {
            protocol,
            packets: p,
            bytes: b,
        })
        .collect();
    protocol_counts.sort_by(|a, b| b.packets.cmp(&a.packets));

    let risk_findings = detect_risks(&hosts, &packets);

    CaptureResult {
        source_file,
        format,
        total_packets,
        total_bytes,
        hosts,
        conversations,
        protocol_counts,
        risk_findings,
    }
}

// ── Risk detection ────────────────────────────────────────────────────────────

const DANGEROUS_PORTS: &[(u16, &str, &str)] = &[
    (23,    "Telnet",        "Plaintext credentials transmitted"),
    (21,    "FTP",           "Plaintext FTP session observed"),
    (69,    "TFTP",          "Unauthenticated file transfer detected"),
    (139,   "NetBIOS",       "NetBIOS session traffic (EternalBlue risk)"),
    (445,   "SMB",           "SMB traffic (potential lateral movement)"),
    (3389,  "RDP",           "Exposed RDP session observed"),
    (5900,  "VNC",           "VNC traffic observed (often weak auth)"),
    (6379,  "Redis",         "Redis traffic — should not be network-accessible"),
    (27017, "MongoDB",       "MongoDB traffic — unauthenticated by default"),
    (9200,  "Elasticsearch", "Elasticsearch traffic — unauthenticated by default"),
    (2375,  "Docker API",    "Unauthenticated Docker API exposed"),
];

const PLAIN_HTTP_PORTS: &[u16] = &[80, 8080, 8000, 8008];

fn detect_risks(
    hosts: &[CaptureHost],
    packets: &[PacketInfo],
) -> Vec<CaptureFinding> {
    let mut findings = Vec::new();

    // Flag dangerous destination ports
    let mut seen: std::collections::HashSet<(String, u16)> = std::collections::HashSet::new();
    for pkt in packets {
        if let Some(port) = pkt.dst_port {
            if let Some(&(_, svc, reason)) = DANGEROUS_PORTS.iter().find(|&&(p, _, _)| p == port) {
                let key = (pkt.dst_ip.clone(), port);
                if seen.insert(key) {
                    findings.push(CaptureFinding {
                        severity: RiskSeverity::High,
                        src_ip: Some(pkt.src_ip.clone()),
                        dst_ip: Some(pkt.dst_ip.clone()),
                        port: Some(port),
                        description: format!("{} — {}", svc, reason),
                    });
                }
            }
        }
    }

    // Flag plaintext HTTP
    let mut http_hosts: std::collections::HashSet<String> = std::collections::HashSet::new();
    for pkt in packets {
        if let Some(port) = pkt.dst_port {
            if PLAIN_HTTP_PORTS.contains(&port) && http_hosts.insert(pkt.dst_ip.clone()) {
                findings.push(CaptureFinding {
                    severity: RiskSeverity::Medium,
                    src_ip: Some(pkt.src_ip.clone()),
                    dst_ip: Some(pkt.dst_ip.clone()),
                    port: Some(port),
                    description: format!(
                        "Plaintext HTTP traffic to {} on port {} — consider HTTPS",
                        pkt.dst_ip, port
                    ),
                });
            }
        }
    }

    // Flag potential port-scanning hosts (many unique dst ports in short burst)
    for host in hosts {
        if host.listening_ports.len() == 0 && host.packets_sent > 500 {
            findings.push(CaptureFinding {
                severity: RiskSeverity::Medium,
                src_ip: Some(host.ip.clone()),
                dst_ip: None,
                port: None,
                description: format!(
                    "{} sent {} packets — possible port scan or flood source",
                    host.ip, host.packets_sent
                ),
            });
        }
    }

    findings.sort_by(|a, b| severity_order(&a.severity).cmp(&severity_order(&b.severity)));
    findings
}

fn severity_order(s: &RiskSeverity) -> u8 {
    match s {
        RiskSeverity::Critical => 0,
        RiskSeverity::High => 1,
        RiskSeverity::Medium => 2,
        RiskSeverity::Low => 3,
        RiskSeverity::Info => 4,
    }
}

// ── Parse Ethernet frame → PacketInfo ─────────────────────────────────────────

fn parse_ethernet(data: &[u8], length: u64) -> Option<PacketInfo> {
    let sliced = SlicedPacket::from_ethernet(data).ok()?;

    let (src_ip, dst_ip) = match &sliced.net {
        Some(InternetSlice::Ipv4(ipv4)) => (
            ipv4.header().source_addr().to_string(),
            ipv4.header().destination_addr().to_string(),
        ),
        Some(InternetSlice::Ipv6(ipv6)) => (
            ipv6.header().source_addr().to_string(),
            ipv6.header().destination_addr().to_string(),
        ),
        _ => return None,
    };

    let (protocol, dst_port) = match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => ("TCP".into(), Some(tcp.destination_port())),
        Some(TransportSlice::Udp(udp)) => ("UDP".into(), Some(udp.destination_port())),
        Some(TransportSlice::Icmpv4(_)) => ("ICMPv4".into(), None),
        Some(TransportSlice::Icmpv6(_)) => ("ICMPv6".into(), None),
        _ => ("OTHER".into(), None),
    };

    Some(PacketInfo { src_ip, dst_ip, protocol, dst_port, length })
}

// ── pcap parser ───────────────────────────────────────────────────────────────

pub fn parse_pcap(path: &str) -> anyhow::Result<CaptureResult> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let mut pcap_reader = PcapReader::new(reader)?;

    let mut packets = Vec::new();
    let mut total_bytes = 0u64;

    while let Some(pkt) = pcap_reader.next_packet() {
        let pkt = pkt?;
        let len = pkt.orig_len as u64;
        total_bytes += len;

        if let Some(info) = parse_ethernet(&pkt.data, len) {
            packets.push(info);
        }

        if packets.len() >= MAX_PACKETS {
            break;
        }
    }

    let filename = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path)
        .to_string();

    Ok(build_result(filename, CaptureFormat::Pcap, packets, total_bytes))
}

// ── pcapng parser ─────────────────────────────────────────────────────────────

pub fn parse_pcapng(path: &str) -> anyhow::Result<CaptureResult> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let mut ng_reader = PcapNgReader::new(reader)?;

    let mut packets = Vec::new();
    let mut total_bytes = 0u64;

    while let Some(block) = ng_reader.next_block() {
        let block = block?;
        let (data, len): (Vec<u8>, u64) = match block {
            Block::EnhancedPacket(epb) => {
                (epb.data.into_owned(), epb.original_len as u64)
            }
            Block::SimplePacket(spb) => {
                (spb.data.into_owned(), spb.original_len as u64)
            }
            _ => continue,
        };

        total_bytes += len;

        if let Some(info) = parse_ethernet(&data, len) {
            packets.push(info);
        }

        if packets.len() >= MAX_PACKETS {
            break;
        }
    }

    let filename = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path)
        .to_string();

    Ok(build_result(filename, CaptureFormat::Pcapng, packets, total_bytes))
}

// ── tshark JSON parser ────────────────────────────────────────────────────────
// Parses output of: tshark -r capture.pcap -T json

pub fn parse_tshark_json(path: &str) -> anyhow::Result<CaptureResult> {
    let content = std::fs::read_to_string(path)?;
    let root: serde_json::Value = serde_json::from_str(&content)?;

    let entries = root
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Expected a JSON array at root"))?;

    let mut packets = Vec::new();
    let mut total_bytes = 0u64;

    for entry in entries.iter().take(MAX_PACKETS) {
        let layers = match entry
            .get("_source")
            .and_then(|s| s.get("layers"))
        {
            Some(l) => l,
            None => continue,
        };

        // Frame length
        let frame_len: u64 = layers
            .get("frame")
            .and_then(|f| f.get("frame.len"))
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        total_bytes += frame_len;

        // Prefer IPv4, fall back to IPv6
        let (src_ip, dst_ip) = if let Some(ip) = layers.get("ip") {
            let src = ip.get("ip.src").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let dst = ip.get("ip.dst").and_then(|v| v.as_str()).unwrap_or("").to_string();
            (src, dst)
        } else if let Some(ip6) = layers.get("ipv6") {
            let src = ip6.get("ipv6.src").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let dst = ip6.get("ipv6.dst").and_then(|v| v.as_str()).unwrap_or("").to_string();
            (src, dst)
        } else {
            continue; // No IP layer
        };

        if src_ip.is_empty() || dst_ip.is_empty() {
            continue;
        }

        // Transport
        let (protocol, dst_port) = if let Some(tcp) = layers.get("tcp") {
            let dp = tcp.get("tcp.dstport").and_then(|v| v.as_str()).and_then(|s| s.parse().ok());
            ("TCP".into(), dp)
        } else if let Some(udp) = layers.get("udp") {
            let dp = udp.get("udp.dstport").and_then(|v| v.as_str()).and_then(|s| s.parse().ok());
            ("UDP".into(), dp)
        } else if layers.get("icmp").is_some() {
            ("ICMPv4".into(), None)
        } else if layers.get("icmpv6").is_some() {
            ("ICMPv6".into(), None)
        } else {
            // Use frame.protocols as fallback label
            let proto = layers
                .get("frame")
                .and_then(|f| f.get("frame.protocols"))
                .and_then(|v| v.as_str())
                .unwrap_or("OTHER")
                .to_string();
            (proto, None)
        };

        packets.push(PacketInfo {
            src_ip,
            dst_ip,
            protocol,
            dst_port,
            length: frame_len,
        });
    }

    let filename = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path)
        .to_string();

    Ok(build_result(filename, CaptureFormat::TsharkJson, packets, total_bytes))
}

// ── Auto-detect format and parse ──────────────────────────────────────────────

/// Maximum capture file size accepted (500 MB). Prevents memory exhaustion
/// from maliciously large or corrupted capture files.
const MAX_CAPTURE_FILE_BYTES: u64 = 500 * 1024 * 1024;

pub fn parse_capture_file(path: &str) -> anyhow::Result<CaptureResult> {
    // Enforce file size limit before reading any data
    let file_size = std::fs::metadata(path)
        .map(|m| m.len())
        .unwrap_or(0);
    if file_size > MAX_CAPTURE_FILE_BYTES {
        anyhow::bail!(
            "Capture file is too large ({:.1} MB). Maximum allowed size is 500 MB.",
            file_size as f64 / (1024.0 * 1024.0)
        );
    }

    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "json" => parse_tshark_json(path),
        "pcapng" | "npcapng" => parse_pcapng(path),
        "pcap" | "cap" => {
            // Try pcapng first (superset format), fall back to pcap
            parse_pcapng(path).or_else(|_| parse_pcap(path))
        }
        _ => anyhow::bail!(
            "Unsupported file extension '.{}'. Supported: .pcap, .pcapng, .cap, .json (tshark export)",
            ext
        ),
    }
}
