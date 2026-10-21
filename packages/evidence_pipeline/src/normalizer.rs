use crate::schema::NetworkEvent;
use std::net::IpAddr;

pub fn normalize_event(
    mut event: NetworkEvent,
    capture_id: &str,
    analysis_run_id: &str,
    pipeline_version: &str,
) -> NetworkEvent {
    // 1. Link layer normalization
    if let Some(link) = &mut event.link_layer {
        if let Some(mac) = &link.source_mac {
            link.source_mac = Some(mac.to_uppercase());
        }
        if let Some(mac) = &link.destination_mac {
            link.destination_mac = Some(mac.to_uppercase());
        }
    }

    // 2. Network layer canonicalization
    if let Some(net) = &mut event.network_layer {
        if let Some(src) = &net.source_ip {
            if let Ok(ip) = src.parse::<IpAddr>() {
                net.source_ip = Some(ip.to_string());
                if net.version.is_none() {
                    net.version = Some(match ip {
                        IpAddr::V4(_) => "IPv4".to_string(),
                        IpAddr::V6(_) => "IPv6".to_string(),
                    });
                }
            }
        }
        if let Some(dst) = &net.destination_ip {
            if let Ok(ip) = dst.parse::<IpAddr>() {
                net.destination_ip = Some(ip.to_string());
                if net.version.is_none() {
                    net.version = Some(match ip {
                        IpAddr::V4(_) => "IPv4".to_string(),
                        IpAddr::V6(_) => "IPv6".to_string(),
                    });
                }
            }
        }
    }

    // 3. Transport layer normalization
    if let Some(trans) = &mut event.transport_layer {
        if let Some(proto) = &trans.protocol {
            trans.protocol = Some(proto.to_uppercase());
        }
    }

    // 4. Enrich provenance with authoritative capture and run identity
    event.provenance.capture_id = Some(capture_id.to_string());
    event.provenance.analysis_run_id = Some(analysis_run_id.to_string());
    event.provenance.pipeline_version = Some(pipeline_version.to_string());

    event
}
