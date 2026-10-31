//! Link-layer stripping for libpcap frames.
//!
//! WinDivert's network layer starts at the IP header, so on Windows
//! [`crate::packet::parse_udp`] is enough. libpcap hands over the frame as it
//! appeared on the wire. On the `any` pseudo-device Linux uses a cooked header
//! (SLL2 on current libpcap, SLL on older releases); a named interface is
//! normally Ethernet. This module removes those headers and leaves the IP
//! packet to the existing parser.
//!
//! The link-type numbers are `LINKTYPE_*` values, which is what libpcap
//! reports. `DLT_RAW` is 12 on most platforms while the standardised
//! `LINKTYPE_RAW` is 101, so both are accepted.

use crate::packet::{parse_udp, UdpView};

const LINKTYPE_NULL: i32 = 0;
const LINKTYPE_ETHERNET: i32 = 1;
const LINKTYPE_RAW_BSD: i32 = 12;
const LINKTYPE_RAW: i32 = 101;
const LINKTYPE_LOOP: i32 = 108;
const LINKTYPE_LINUX_SLL: i32 = 113;
const LINKTYPE_IPV4: i32 = 228;
const LINKTYPE_IPV6: i32 = 229;
const LINKTYPE_LINUX_SLL2: i32 = 276;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88A8;
const ETHERTYPE_VLAN_9100: u16 = 0x9100;

/// Parse a libpcap frame for the given link type and return its UDP view.
///
/// Returns `None` for a link type this module does not know, for a frame that
/// is too short to contain its link-layer header, and for anything
/// [`parse_udp`] rejects.
pub fn parse_frame(linktype: i32, frame: &[u8]) -> Option<UdpView<'_>> {
    let ip = match linktype {
        LINKTYPE_ETHERNET => strip_ethernet(frame)?,
        LINKTYPE_LINUX_SLL => strip_sll(frame)?,
        LINKTYPE_LINUX_SLL2 => strip_sll2(frame)?,
        LINKTYPE_NULL => strip_null(frame, false)?,
        LINKTYPE_LOOP => strip_null(frame, true)?,
        // Raw IP starts at the IP header, as WinDivert's packets do.
        LINKTYPE_RAW | LINKTYPE_RAW_BSD | LINKTYPE_IPV4 | LINKTYPE_IPV6 => frame,
        _ => return None,
    };
    parse_udp(ip)
}

/// Ethernet II, including any number of 802.1Q/802.1ad tags.
fn strip_ethernet(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 14 {
        return None;
    }
    let mut offset = 12;
    loop {
        let ethertype = read_be_u16(frame, offset)?;
        offset += 2;
        match ethertype {
            ETHERTYPE_VLAN | ETHERTYPE_QINQ | ETHERTYPE_VLAN_9100 => {
                // The tag control information is two bytes; the next ethertype
                // follows it.
                offset += 2;
                if offset > frame.len() {
                    return None;
                }
            }
            ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => return frame.get(offset..),
            _ => return None,
        }
    }
}

/// Linux cooked capture v1: 16 bytes, protocol at offset 14.
fn strip_sll(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 16 {
        return None;
    }
    let protocol = read_be_u16(frame, 14)?;
    is_ip(protocol).then(|| &frame[16..])
}

/// Linux cooked capture v2: 20 bytes, protocol at offset 0.
fn strip_sll2(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 20 {
        return None;
    }
    let protocol = read_be_u16(frame, 0)?;
    is_ip(protocol).then(|| &frame[20..])
}

/// BSD loopback. `NULL` stores the address family in host byte order, `LOOP`
/// in network byte order.
fn strip_null(frame: &[u8], network_order: bool) -> Option<&[u8]> {
    let bytes: [u8; 4] = frame.get(..4)?.try_into().ok()?;
    let family = if network_order {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_ne_bytes(bytes)
    };
    // AF_INET is 2 everywhere. AF_INET6 is 10 on Linux and 24, 28 or 30 on the
    // BSDs depending on the release.
    matches!(family, 2 | 10 | 24 | 28 | 30).then(|| &frame[4..])
}

fn read_be_u16(frame: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = frame.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

fn is_ip(ethertype: u16) -> bool {
    matches!(ethertype, ETHERTYPE_IPV4 | ETHERTYPE_IPV6)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_udp(source: u16, destination: u16, payload: &[u8]) -> Vec<u8> {
        let total = 20 + 8 + payload.len();
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[9] = 17;
        packet.extend_from_slice(&source.to_be_bytes());
        packet.extend_from_slice(&destination.to_be_bytes());
        packet.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(payload);
        packet
    }

    fn ipv6_udp(source: u16, destination: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[6] = 17;
        let mut body = Vec::new();
        body.extend_from_slice(&source.to_be_bytes());
        body.extend_from_slice(&destination.to_be_bytes());
        body.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(payload);
        packet[4..6].copy_from_slice(&(body.len() as u16).to_be_bytes());
        packet.extend_from_slice(&body);
        packet
    }

    fn ethernet(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn vlan(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x2a]); // TCI
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn sll(protocol: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 14];
        frame.extend_from_slice(&protocol.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn sll2(protocol: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = protocol.to_be_bytes().to_vec();
        frame.extend_from_slice(&[0u8; 18]);
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn strips_ethernet() {
        let packet = ipv4_udp(51000, 20501, b"ethernet");
        let frame = ethernet(ETHERTYPE_IPV4, &packet);
        let view = parse_frame(LINKTYPE_ETHERNET, &frame).expect("parses");
        assert_eq!(view.destination_port, 20501);
        assert_eq!(view.payload, b"ethernet");
    }

    #[test]
    fn strips_vlan_tags() {
        let packet = ipv4_udp(20501, 51000, b"vlan");
        let frame = vlan(ETHERTYPE_IPV4, &packet);
        let view = parse_frame(LINKTYPE_ETHERNET, &frame).expect("parses");
        assert_eq!(view.source_port, 20501);
        assert_eq!(view.payload, b"vlan");
    }

    #[test]
    fn strips_linux_cooked_headers() {
        let packet = ipv4_udp(51000, 20501, b"sll");

        let frame = sll(ETHERTYPE_IPV4, &packet);
        let view = parse_frame(LINKTYPE_LINUX_SLL, &frame).expect("SLL parses");
        assert_eq!(view.payload, b"sll");

        let frame = sll2(ETHERTYPE_IPV4, &packet);
        let view = parse_frame(LINKTYPE_LINUX_SLL2, &frame).expect("SLL2 parses");
        assert_eq!(view.payload, b"sll");
    }

    #[test]
    fn strips_ipv6_over_cooked_headers() {
        let packet = ipv6_udp(51000, 20501, b"v6");
        let frame = sll2(ETHERTYPE_IPV6, &packet);
        let view = parse_frame(LINKTYPE_LINUX_SLL2, &frame).expect("parses");
        assert_eq!(view.destination_port, 20501);
        assert_eq!(view.payload, b"v6");
    }

    #[test]
    fn strips_loopback_headers() {
        let packet = ipv4_udp(51000, 20501, b"loop");

        let mut null = 2u32.to_ne_bytes().to_vec();
        null.extend_from_slice(&packet);
        let view = parse_frame(LINKTYPE_NULL, &null).expect("NULL parses");
        assert_eq!(view.payload, b"loop");

        let mut loop_frame = 2u32.to_be_bytes().to_vec();
        loop_frame.extend_from_slice(&packet);
        let view = parse_frame(LINKTYPE_LOOP, &loop_frame).expect("LOOP parses");
        assert_eq!(view.payload, b"loop");
    }

    #[test]
    fn accepts_raw_ip_link_types() {
        let packet = ipv4_udp(51000, 20501, b"raw");
        for linktype in [LINKTYPE_RAW, LINKTYPE_RAW_BSD, LINKTYPE_IPV4, LINKTYPE_IPV6] {
            let view = parse_frame(linktype, &packet).expect("raw parses");
            assert_eq!(view.payload, b"raw");
        }
    }

    #[test]
    fn rejects_unknown_and_truncated_frames() {
        let packet = ipv4_udp(51000, 20501, b"x");
        assert!(parse_frame(999, &packet).is_none());
        assert!(parse_frame(LINKTYPE_ETHERNET, &[0u8; 13]).is_none());
        assert!(parse_frame(LINKTYPE_LINUX_SLL, &[0u8; 15]).is_none());
        assert!(parse_frame(LINKTYPE_LINUX_SLL2, &[0u8; 19]).is_none());
        assert!(parse_frame(LINKTYPE_NULL, &[0u8; 3]).is_none());

        // A complete header but a non-IP ethertype is not our traffic.
        let frame = ethernet(0x0806, &packet); // ARP
        assert!(parse_frame(LINKTYPE_ETHERNET, &frame).is_none());
    }
}
