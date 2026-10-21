use crate::schema::NetworkEvent;
use regex::Regex;
use std::net::IpAddr;
use std::sync::OnceLock;

static MAC_REGEX: OnceLock<Regex> = OnceLock::new();
static UUID_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_mac_regex() -> &'static Regex {
    MAC_REGEX.get_or_init(|| {
        Regex::new(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$").expect("Invalid MAC regex")
    })
}

fn get_uuid_regex() -> &'static Regex {
    UUID_REGEX.get_or_init(|| {
        Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
            .expect("Invalid UUID regex")
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    InvalidSchemaVersion(String),
    InvalidEventId(String),
    InvalidTimestamp(String),
    MissingSourceId,
    InvalidParserStatus(String),
    InvalidMacAddress(String),
    InvalidIpAddress(String),
    InvalidVlanId(u16),
    InvalidTtl(u8),
    InvalidPayloadHash(String),
    MissingProvenance,
    ProvenanceMismatch(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSchemaVersion(v) => {
                write!(f, "Invalid schema version: expected 1.0.0, got '{}'", v)
            }
            Self::InvalidEventId(id) => write!(f, "Event ID '{}' is not a valid UUID", id),
            Self::InvalidTimestamp(msg) => write!(f, "Invalid timestamp: {}", msg),
            Self::MissingSourceId => write!(f, "source_id is missing or empty"),
            Self::InvalidParserStatus(st) => write!(f, "Invalid parser status: '{}'", st),
            Self::InvalidMacAddress(mac) => write!(f, "Invalid MAC address format: '{}'", mac),
            Self::InvalidIpAddress(ip) => write!(f, "Invalid IP address format: '{}'", ip),
            Self::InvalidVlanId(v) => write!(f, "VLAN ID {} out of range (0-4095)", v),
            Self::InvalidTtl(ttl) => write!(f, "TTL/Hop limit {} invalid", ttl),
            Self::InvalidPayloadHash(h) => {
                write!(f, "Invalid payload SHA-256 hash format: '{}'", h)
            }
            Self::MissingProvenance => write!(f, "Provenance information is missing"),
            Self::ProvenanceMismatch(msg) => write!(f, "Provenance mismatch: {}", msg),
        }
    }
}

impl std::error::Error for ValidationError {}

pub fn validate_event(event: &NetworkEvent, expected_schema: &str) -> Result<(), ValidationError> {
    // 1. Schema version
    if event.schema_version != expected_schema {
        return Err(ValidationError::InvalidSchemaVersion(
            event.schema_version.clone(),
        ));
    }

    // 2. Event ID
    if !get_uuid_regex().is_match(&event.event_id) {
        return Err(ValidationError::InvalidEventId(event.event_id.clone()));
    }

    // 3. Timestamps
    if event.timestamp_ns == 0 {
        return Err(ValidationError::InvalidTimestamp(
            "timestamp_ns cannot be zero".into(),
        ));
    }
    if event.timestamp_iso.is_empty() {
        return Err(ValidationError::InvalidTimestamp(
            "timestamp_iso cannot be empty".into(),
        ));
    }

    // 4. Source ID
    if event.source_id.trim().is_empty() {
        return Err(ValidationError::MissingSourceId);
    }

    // 5. Parser Status
    let valid_statuses = [
        "ok",
        "incomplete",
        "malformed",
        "unsupported_protocol",
        "checksum_error",
        "truncated",
    ];
    if !valid_statuses.contains(&event.parser_status.status.as_str()) {
        return Err(ValidationError::InvalidParserStatus(
            event.parser_status.status.clone(),
        ));
    }

    // 6. Link Layer
    if let Some(link) = &event.link_layer {
        if let Some(src_mac) = &link.source_mac {
            if !get_mac_regex().is_match(src_mac) {
                return Err(ValidationError::InvalidMacAddress(src_mac.clone()));
            }
        }
        if let Some(dst_mac) = &link.destination_mac {
            if !get_mac_regex().is_match(dst_mac) {
                return Err(ValidationError::InvalidMacAddress(dst_mac.clone()));
            }
        }
        if let Some(vlan) = link.vlan_id {
            if vlan > 4095 {
                return Err(ValidationError::InvalidVlanId(vlan));
            }
        }
    }

    // 7. Network Layer
    if let Some(net) = &event.network_layer {
        if let Some(src_ip) = &net.source_ip {
            if src_ip.parse::<IpAddr>().is_err() {
                return Err(ValidationError::InvalidIpAddress(src_ip.clone()));
            }
        }
        if let Some(dst_ip) = &net.destination_ip {
            if dst_ip.parse::<IpAddr>().is_err() {
                return Err(ValidationError::InvalidIpAddress(dst_ip.clone()));
            }
        }
    }

    // 8. Application Layer
    if let Some(app) = &event.application_layer {
        if let Some(hash) = &app.payload_hash_sha256 {
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ValidationError::InvalidPayloadHash(hash.clone()));
            }
        }
    }

    Ok(())
}
