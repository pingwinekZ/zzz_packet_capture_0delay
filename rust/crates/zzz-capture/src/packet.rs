//! Minimal IPv4/IPv6 + UDP header walking.
//!
//! WinDivert's network layer hands over an IP packet with no link-layer header,
//! so this is all the dissecting we need: find the UDP header, check the port, and
//! slice out the payload. Everything here is pure and unit tested against
//! hand-built packets, because on a live capture we only get one shot at getting
//! it right.

/// A parsed UDP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpView<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: &'a [u8],
}

const IPPROTO_UDP: u8 = 17;

/// Parse an IPv4 or IPv6 packet and return its UDP header, if it has one.
///
/// Returns `None` for anything that is not a complete, first-fragment UDP
/// datagram: non-IP versions, truncated headers, other protocols, and fragments
/// that do not start at the UDP header.
pub fn parse_udp(packet: &[u8]) -> Option<UdpView<'_>> {
    let first = *packet.first()?;
    match first >> 4 {
        4 => parse_ipv4(packet),
        6 => parse_ipv6(packet),
        _ => None,
    }
}

fn parse_ipv4(packet: &[u8]) -> Option<UdpView<'_>> {
    if packet.len() < 20 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0F) * 4;
    if header_len < 20 || packet.len() < header_len {
        return None;
    }
    if packet[9] != IPPROTO_UDP {
        return None;
    }

    // A fragment that is not the first one carries no UDP header; even for the
    // first fragment we only ever see a partial payload, so take what is there.
    let flags_and_offset = u16::from_be_bytes([packet[6], packet[7]]);
    if flags_and_offset & 0x1FFF != 0 {
        return None;
    }

    // Trust the header, not the buffer: the capture can be one byte short.
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let end = if total_len >= header_len {
        total_len.min(packet.len())
    } else {
        packet.len()
    };
    parse_udp_header(&packet[header_len..end])
}

fn parse_ipv6(packet: &[u8]) -> Option<UdpView<'_>> {
    const BASE_HEADER: usize = 40;
    if packet.len() < BASE_HEADER {
        return None;
    }

    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let end = (BASE_HEADER + payload_len).min(packet.len());

    let mut next_header = packet[6];
    let mut offset = BASE_HEADER;
    // Walk the extension headers we can see. A fragment header means the UDP
    // header may not be here at all, so give up rather than mis-parse.
    loop {
        match next_header {
            IPPROTO_UDP => return parse_udp_header(&packet[offset.min(end)..end]),
            0 | 43 | 60 => {
                // Hop-by-hop, routing and destination-options: length is (n+1)*8.
                let header = packet.get(offset..offset + 2)?;
                offset += (usize::from(header[1]) + 1) * 8;
                next_header = header[0];
                if offset > end {
                    return None;
                }
            }
            44 => return None,
            59 => return None, // no next header
            _ => return None,
        }
    }
}

fn parse_udp_header(datagram: &[u8]) -> Option<UdpView<'_>> {
    if datagram.len() < 8 {
        return None;
    }
    let source_port = u16::from_be_bytes([datagram[0], datagram[1]]);
    let destination_port = u16::from_be_bytes([datagram[2], datagram[3]]);
    let udp_len = usize::from(u16::from_be_bytes([datagram[4], datagram[5]]));

    // A zero length field means "unspecified" for IPv6 jumbograms; otherwise it
    // includes the 8-byte header.
    let payload_end = if udp_len >= 8 {
        udp_len.min(datagram.len())
    } else {
        datagram.len()
    };

    Some(UdpView {
        source_port,
        destination_port,
        payload: &datagram[8..payload_end],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_udp(source: u16, destination: u16, payload: &[u8], options: usize) -> Vec<u8> {
        let header_len = 20 + options;
        let total = header_len + 8 + payload.len();
        let mut packet = vec![0u8; header_len];
        packet[0] = 0x40 | ((header_len / 4) as u8);
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[9] = IPPROTO_UDP;
        packet.extend_from_slice(&source.to_be_bytes());
        packet.extend_from_slice(&destination.to_be_bytes());
        packet.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0]); // checksum
        packet.extend_from_slice(payload);
        packet
    }

    fn ipv6_udp(source: u16, destination: u16, payload: &[u8], extension: bool) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[6] = if extension { 0 } else { IPPROTO_UDP }; // hop-by-hop or UDP
        let mut body = Vec::new();
        if extension {
            body.extend_from_slice(&[IPPROTO_UDP, 0, 0, 0, 0, 0, 0, 0]);
        }
        body.extend_from_slice(&source.to_be_bytes());
        body.extend_from_slice(&destination.to_be_bytes());
        body.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(payload);
        packet[4..6].copy_from_slice(&(body.len() as u16).to_be_bytes());
        packet.extend_from_slice(&body);
        packet
    }

    #[test]
    fn parses_an_ipv4_udp_datagram() {
        let packet = ipv4_udp(51000, 20501, b"payload", 0);
        let view = parse_udp(&packet).expect("parses");
        assert_eq!(view.source_port, 51000);
        assert_eq!(view.destination_port, 20501);
        assert_eq!(view.payload, b"payload");
    }

    #[test]
    fn honours_ipv4_options_when_finding_the_udp_header() {
        let packet = ipv4_udp(20501, 51000, b"with options", 12);
        let view = parse_udp(&packet).expect("parses");
        assert_eq!(view.source_port, 20501);
        assert_eq!(view.payload, b"with options");
    }

    #[test]
    fn parses_an_ipv6_udp_datagram() {
        let packet = ipv6_udp(51000, 20501, b"v6 payload", false);
        let view = parse_udp(&packet).expect("parses");
        assert_eq!(view.destination_port, 20501);
        assert_eq!(view.payload, b"v6 payload");
    }

    #[test]
    fn walks_ipv6_extension_headers() {
        let packet = ipv6_udp(51000, 20501, b"after hop-by-hop", true);
        let view = parse_udp(&packet).expect("parses");
        assert_eq!(view.destination_port, 20501);
        assert_eq!(view.payload, b"after hop-by-hop");
    }

    #[test]
    fn rejects_what_it_cannot_parse() {
        assert_eq!(parse_udp(&[]), None);
        assert_eq!(parse_udp(&[0x45, 0x00]), None);

        // IPv4 carrying TCP, not UDP.
        let mut tcp = ipv4_udp(1, 2, b"x", 0);
        tcp[9] = 6;
        assert_eq!(parse_udp(&tcp), None);

        // A non-first fragment has no UDP header at the offset we would read.
        let mut fragment = ipv4_udp(1, 2, b"x", 0);
        fragment[7] = 0x01; // fragment offset 1
        assert_eq!(parse_udp(&fragment), None);

        // IPv6 with a fragment header: the payload is incomplete by design.
        let mut fragmented = ipv6_udp(1, 2, b"x", false);
        fragmented[6] = 44;
        assert_eq!(parse_udp(&fragmented), None);

        // Truncated UDP header.
        let packet = ipv4_udp(1, 2, b"", 0);
        assert_eq!(parse_udp(&packet[..22]), None);
    }

    #[test]
    fn truncation_shrinks_the_payload_instead_of_panicking() {
        let packet = ipv4_udp(1, 2, b"0123456789", 0);
        // Drop the last four bytes of payload but leave the declared length alone.
        let view = parse_udp(&packet[..packet.len() - 4]).expect("parses what is there");
        assert_eq!(view.payload, b"012345");
    }

    #[test]
    fn a_zero_total_length_falls_back_to_the_buffer() {
        let mut packet = ipv4_udp(1, 20501, b"no length", 0);
        packet[2] = 0;
        packet[3] = 0;
        let view = parse_udp(&packet).expect("parses");
        assert_eq!(view.payload, b"no length");
    }
}
