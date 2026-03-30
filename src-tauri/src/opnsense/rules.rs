use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Pass,
    Block,
    Reject,
}

impl std::fmt::Display for RuleAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleAction::Pass => write!(f, "pass"),
            RuleAction::Block => write!(f, "block"),
            RuleAction::Reject => write!(f, "reject"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RuleDirection {
    In,
    Out,
}

impl std::fmt::Display for RuleDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleDirection::In => write!(f, "in"),
            RuleDirection::Out => write!(f, "out"),
        }
    }
}

/// Mirrors the OPNsense firewall/filter MVC rule structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    /// Unique identifier from OPNsense (None for proposed new rules)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    pub action: RuleAction,
    pub direction: RuleDirection,
    pub interface: String,
    pub protocol: String,
    /// Source address or "any"
    pub source_net: String,
    /// Destination address or "any"
    pub destination_net: String,
    /// Destination port (e.g. "22", "443", "any")
    pub destination_port: String,
    pub description: String,
    pub enabled: bool,
    /// If true this rule only logs; no block/pass action taken (permissive tier)
    pub log: bool,
}

impl FirewallRule {
    /// Validate that rule fields are safe to send to the OPNsense API.
    /// Rejects values that are too long, contain control characters, or
    /// are clearly invalid (e.g. non-numeric port strings).
    pub fn validate(&self) -> Result<(), String> {
        validate_net_spec(&self.source_net, "source_net")?;
        validate_net_spec(&self.destination_net, "destination_net")?;
        validate_port_spec(&self.destination_port, "destination_port")?;
        validate_safe_string(&self.description, "description", 512)?;
        validate_safe_string(&self.interface, "interface", 64)?;
        validate_safe_string(&self.protocol, "protocol", 16)?;
        Ok(())
    }
}

/// Accept "any", a bare IP, or a CIDR. Reject everything else.
fn validate_net_spec(value: &str, field: &str) -> Result<(), String> {
    if value == "any" {
        return Ok(());
    }
    if value.len() > 64 {
        return Err(format!("{field} value is too long"));
    }
    // Only allow characters valid in IPs and CIDRs: digits, dots, colons, slashes
    let ok = value.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '/' | '[' | ']'));
    if !ok {
        return Err(format!("{field} contains invalid characters"));
    }
    Ok(())
}

/// Accept "any", a plain port number (1-65535), or a range "N:M".
fn validate_port_spec(value: &str, field: &str) -> Result<(), String> {
    if value == "any" {
        return Ok(());
    }
    // Allow "N" or "N:M" range notation
    for part in value.split(':') {
        let p: u16 = part.parse()
            .map_err(|_| format!("{field} must be 'any', a port number, or a range N:M"))?;
        if p == 0 {
            return Err(format!("{field} port 0 is not valid"));
        }
    }
    Ok(())
}

/// Reject strings with control characters or that exceed the length cap.
fn validate_safe_string(value: &str, field: &str, max_len: usize) -> Result<(), String> {
    if value.len() > max_len {
        return Err(format!("{field} exceeds maximum length of {max_len} characters"));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(format!("{field} contains control characters"));
    }
    Ok(())
}

/// OPNsense addRule / setRule POST body shape
#[derive(Debug, Serialize)]
pub struct OPNsenseRulePayload {
    pub rule: OPNsenseRuleFields,
}

#[derive(Debug, Serialize)]
pub struct OPNsenseRuleFields {
    pub action: String,
    pub direction: String,
    pub interface: String,
    pub protocol: String,
    pub source_net: String,
    pub destination_net: String,
    pub destination_port: String,
    pub description: String,
    pub enabled: String,
    pub log: String,
}

impl From<&FirewallRule> for OPNsenseRulePayload {
    fn from(r: &FirewallRule) -> Self {
        OPNsenseRulePayload {
            rule: OPNsenseRuleFields {
                action: r.action.to_string(),
                direction: r.direction.to_string(),
                interface: r.interface.clone(),
                protocol: r.protocol.clone(),
                source_net: r.source_net.clone(),
                destination_net: r.destination_net.clone(),
                destination_port: r.destination_port.clone(),
                description: r.description.clone(),
                enabled: if r.enabled { "1" } else { "0" }.to_string(),
                log: if r.log { "1" } else { "0" }.to_string(),
            },
        }
    }
}

/// Response from OPNsense when listing rules
#[derive(Debug, Deserialize)]
pub struct OPNsenseRuleListResponse {
    pub rows: Option<Vec<OPNsenseRuleRow>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OPNsenseRuleRow {
    pub uuid: Option<String>,
    pub action: Option<String>,
    pub direction: Option<String>,
    pub interface: Option<String>,
    pub protocol: Option<String>,
    #[serde(rename = "source_net")]
    pub source_net: Option<String>,
    #[serde(rename = "destination_net")]
    pub destination_net: Option<String>,
    #[serde(rename = "destination_port")]
    pub destination_port: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<String>,
}
