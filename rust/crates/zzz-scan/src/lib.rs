//! Session handling and message decoding — the layer between captured UDP
//! payloads and game data.
//!
//! Ports `src/crypto/session.hpp` and the body of `Pcap::processMessageBody` from
//! `src/pcap/pcap.hpp`. Where the C++ reaches into singletons and keeps the pad in
//! a function-local `static`, a [`Scanner`] here owns its reassembler and its
//! [`Session`], so replaying a dump is a pure function of the dump. That is not
//! only tidier: two scanners can run side by side, which is how the region seed
//! behind a capture is identified instead of being configured by hand.

pub mod model;
pub mod session;
pub mod snapshot;

use std::collections::BTreeMap;

use zzz_crypto::xorpad::XorPad;
use zzz_gamedata::{Datamine, Protonap};
use zzz_wire::kcp::{Direction, Kcp, KcpStats, MessageHeader, MESSAGE_HEADER_SIZE};
use zzz_wire::proto::Message;
use zzz_wire::xor_fields::xor_proto_fields;

pub use model::{
    rarity_key, stat_info, AgentInfo, AvatarSkillLevel, DiscInfo, DiscStat, DressedEquip, StatInfo,
    WeaponInfo,
};
pub use session::{BruteForceMatch, Session, SessionError, BRUTE_FORCE_WINDOW_SECONDS};
pub use snapshot::{ExtractEvent, ExtractSummary, Inventory, ItemChange, SyncResult, Upsert};

/// What decoding one reassembled message produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeEvent {
    /// `PlayerGetTokenScRsp` carried the server's half of the session key.
    ServerRandKey { key: u64 },
    /// The token response arrived but no usable key could be read from it.
    ServerRandKeyFailed { error: SessionError },
    /// The client's seed was recovered and the session pad installed.
    SessionKey { found: BruteForceMatch },
    /// No seed in the window made the body parse.
    SessionKeyNotFound,
    /// A body decrypted and parsed as protobuf.
    Message {
        command_id: u16,
        message: Message,
        bytes: usize,
    },
    /// A body decrypted to bytes that are not protobuf.
    ProtoFailed { command_id: u16, bytes: usize },
}

/// Counters for a whole replay.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DecodeStats {
    /// Messages delivered by the reassembler.
    pub messages: u64,
    /// Messages whose body parsed as protobuf.
    pub decoded: u64,
    /// Messages whose body did not parse.
    pub proto_failures: u64,
    /// Messages whose body was empty after decryption.
    pub empty_bodies: u64,
}

/// The first few decoded messages, for eyeballing a capture that is new to you.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedMessage {
    pub command_id: u16,
    pub bytes: usize,
    pub fields: usize,
}

/// Turns reassembled message bodies into events. The port of
/// `Pcap::processMessageBody`.
#[derive(Debug)]
pub struct Decoder<'a> {
    session: Session,
    datamine: &'a Datamine,
    nap: &'a Protonap,
    stats: DecodeStats,
}

impl<'a> Decoder<'a> {
    pub fn new(session: Session, datamine: &'a Datamine, nap: &'a Protonap) -> Self {
        Self {
            session,
            datamine,
            nap,
            stats: DecodeStats::default(),
        }
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn stats(&self) -> &DecodeStats {
        &self.stats
    }

    /// The field numbers and command ids the extraction pass reads.
    pub fn datamine(&self) -> &'a Datamine {
        self.datamine
    }

    /// `Pcap::processMessageBody`, one message at a time.
    ///
    /// A single message can produce two events: the one that completes the
    /// handshake is also a normal message that parses.
    pub fn feed(&mut self, message_bytes: &[u8], unix_seconds: i64) -> Vec<DecodeEvent> {
        let mut events = Vec::new();
        if message_bytes.len() < MESSAGE_HEADER_SIZE {
            return events;
        }
        let Ok(header) = MessageHeader::decode(message_bytes) else {
            return events;
        };

        // `messageBytes | drop(size + headLength) | take(bodyLength)`. `take`
        // clamps to what is there, so a body that runs past the end of the message
        // yields the bytes present rather than nothing: a truncated capture still
        // gets its partial body decrypted and reported.
        let start = MESSAGE_HEADER_SIZE + header.head_length as usize;
        let end = start
            .saturating_add(header.body_length as usize)
            .min(message_bytes.len());
        let body = if start <= end {
            &message_bytes[start..end]
        } else {
            &[]
        };
        let decrypted = self.session.decrypt_body(body);
        self.stats.messages += 1;

        let command_id = header.command_id;
        let is_token_response = u32::from(command_id) == self.datamine.cmd_player_get_token_sc_rsp;

        // The token response is the one message decrypted with the region pad only,
        // so it is handled on its own and does not fall through to the parser.
        if self.session.server_rand_key.is_none() && is_token_response {
            match Session::extract_server_rand_key(&decrypted) {
                Ok(key) => {
                    self.session.server_rand_key = Some(key);
                    events.push(DecodeEvent::ServerRandKey { key });
                }
                Err(error) => events.push(DecodeEvent::ServerRandKeyFailed { error }),
            }
            return events;
        }

        // Until the pad is known, every sufficiently long body is a chance to
        // recover the seed. The declared length is used, matching the original.
        if self.session.server_rand_key.is_some()
            && !self.session.pad_ready()
            && header.body_length >= 32
        {
            match self.session.derive_session_key(body, unix_seconds) {
                Some(found) => events.push(DecodeEvent::SessionKey { found }),
                None => events.push(DecodeEvent::SessionKeyNotFound),
            }
        }

        if decrypted.is_empty() {
            self.stats.empty_bodies += 1;
            return events;
        }

        match Message::decode(&decrypted) {
            Ok(mut message) => {
                // The game XORs selected scalar *values*, not field numbers: the
                // descriptor for this command lists which fields are obfuscated
                // and with what, and the pass below undoes it in place (recursing
                // into submessages) before anything reads a value.
                xor_proto_fields(&mut message, self.nap.entry_by_cmd(command_id), self.nap);
                self.stats.decoded += 1;
                events.push(DecodeEvent::Message {
                    command_id,
                    message,
                    bytes: decrypted.len(),
                });
            }
            Err(_) => {
                self.stats.proto_failures += 1;
                events.push(DecodeEvent::ProtoFailed {
                    command_id,
                    bytes: decrypted.len(),
                });
            }
        }

        events
    }
}

/// One capture's worth of state: the KCP reassembler plus the decoder, and what
/// was seen along the way.
#[derive(Debug)]
pub struct Scanner<'a> {
    kcp: Kcp,
    decoder: Decoder<'a>,
    /// The player's discs, engines and agents, built up as syncs arrive.
    inventory: Inventory,
    /// What the extraction pass did, for reporting.
    extract: ExtractSummary,
    /// The item-level changes of the packet being fed, so a live caller can log
    /// what happened rather than only how much.
    last_changes: Vec<ItemChange>,
    /// Whether the packet being fed completed a load response. Its changes are
    /// the baseline inventory, not deltas — see [`Scanner::last_feed_had_load`].
    last_had_load: bool,
    /// Command id -> number of messages decoded with it.
    pub commands: BTreeMap<u16, u64>,
    /// The first few decoded messages, in capture order.
    pub first: Vec<DecodedMessage>,
}

/// How many of the first messages are remembered for reporting.
const REMEMBERED_MESSAGES: usize = 8;

impl<'a> Scanner<'a> {
    pub fn new(region_pad: XorPad, datamine: &'a Datamine, nap: &'a Protonap) -> Self {
        Self {
            kcp: Kcp::new(),
            decoder: Decoder::new(Session::new(region_pad), datamine, nap),
            inventory: Inventory::new(),
            extract: ExtractSummary::default(),
            last_changes: Vec::new(),
            last_had_load: false,
            commands: BTreeMap::new(),
            first: Vec::new(),
        }
    }

    /// Feed one captured UDP payload and decode whatever messages it completes.
    pub fn feed(
        &mut self,
        data: &[u8],
        direction: Direction,
        unix_seconds: i64,
    ) -> Vec<DecodeEvent> {
        let messages = self.kcp.receive(data, direction, unix_seconds);
        let mut events = Vec::new();
        self.last_changes.clear();
        self.last_had_load = false;
        for message in messages {
            for event in self.decoder.feed(&message, unix_seconds) {
                if let DecodeEvent::Message {
                    command_id,
                    message,
                    bytes,
                } = &event
                {
                    *self.commands.entry(*command_id).or_default() += 1;
                    if self.first.len() < REMEMBERED_MESSAGES {
                        self.first.push(DecodedMessage {
                            command_id: *command_id,
                            bytes: *bytes,
                            fields: message.fields.len(),
                        });
                    }
                    // The extraction the original does in the same place: the
                    // field numbers have been XORed back by now, so a sync can be
                    // interpreted as soon as it decodes.
                    let extracted =
                        self.inventory
                            .apply(*command_id, message, self.decoder.datamine());
                    self.extract.absorb(&extracted);
                    // The item-level changes of this packet, in field order, for
                    // a caller that shows *what* changed rather than only how
                    // much. Cleared at the top of each `feed`.
                    for event in &extracted {
                        match event {
                            ExtractEvent::Discs { .. }
                            | ExtractEvent::Weapons { .. }
                            | ExtractEvent::Avatars { .. } => {
                                self.last_had_load = true;
                            }
                            ExtractEvent::Changes(changes) if !changes.is_empty() => {
                                self.last_changes.extend(changes.iter().cloned());
                            }
                            _ => {}
                        }
                    }
                }
                events.push(event);
            }
        }
        events
    }

    /// The item-level changes the most recent [`Scanner::feed`] produced, in
    /// capture order. Empty when the packet changed nothing.
    pub fn take_changes(&mut self) -> Vec<ItemChange> {
        std::mem::take(&mut self.last_changes)
    }

    /// Whether the most recent [`Scanner::feed`] completed a load response
    /// (`GetEquipDataScRsp`, `GetWeaponDataScRsp` or `GetAvatarDataScRsp`).
    /// Its changes carry the whole baseline inventory, so a live caller skips
    /// logging them as deltas. Captures that start mid-game never see a load,
    /// so this stays false there and nothing is suppressed.
    pub fn last_feed_had_load(&self) -> bool {
        self.last_had_load
    }

    /// The discs, engines and agents extracted so far.
    pub fn inventory(&self) -> &Inventory {
        &self.inventory
    }

    /// What the extraction pass did.
    pub fn extract(&self) -> &ExtractSummary {
        &self.extract
    }

    pub fn session(&self) -> &Session {
        &self.decoder.session
    }

    pub fn stats(&self) -> &DecodeStats {
        self.decoder.stats()
    }

    pub fn kcp_stats(&self) -> &KcpStats {
        self.kcp.stats()
    }

    /// Whether the session pad has been recovered, so later messages decrypt.
    pub fn handshake_complete(&self) -> bool {
        self.decoder.session.pad_ready()
    }

    /// Whether anything at all decoded. This is the test for "is this region seed
    /// the right one?" — with the wrong pad nothing parses.
    pub fn decoded_anything(&self) -> bool {
        self.decoder.stats.decoded > 0 || self.decoder.session.server_rand_key.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use zzz_crypto::b64::b64_encode;
    use zzz_crypto::netrand::{client_rand_key, seed_from_unix_seconds};
    use zzz_crypto::rsa;
    use zzz_crypto::xorpad;
    use zzz_gamedata::GameData;
    use zzz_wire::kcp::{MessageHeader, SegmentHeader};
    use zzz_wire::proto::{Field, Value};
    use zzz_wire::xor_fields::xor_proto_fields;

    const SERVER_RAND_KEY: u64 = 0x0BAD_F00D_DEAD_BEEF;
    const LOGIN_TIME: i64 = 1_760_000_000;
    const CONV: u32 = 0x0142_C90B;

    fn segment(sn: u32, message: &[u8]) -> Vec<u8> {
        let header = SegmentHeader {
            conv: CONV,
            token: 0,
            cmd: 81, // cmdPush
            frg: 0,
            wnd: 128,
            ts: 0,
            sn,
            una: 0,
            len: message.len() as u32,
        };
        let mut out = header.encode().to_vec();
        out.extend_from_slice(message);
        out
    }

    fn message(command_id: u16, body: &[u8]) -> Vec<u8> {
        let header = MessageHeader {
            magic: *b"ZZZ0",
            command_id,
            head_length: 0,
            body_length: body.len() as u32,
        };
        let mut out = header.encode().to_vec();
        out.extend_from_slice(body);
        out
    }

    /// A body of a realistic size: long enough that a wrong pad will not parse.
    fn sync_body() -> Vec<u8> {
        Message {
            fields: vec![
                Field::new(1, Value::LengthDelimited(vec![0x11; 64])),
                Field::new(2, Value::LengthDelimited(vec![0x22; 128])),
            ],
        }
        .encode()
    }

    /// The body of the message that carries the session pad: it is encrypted with
    /// the session pad but has to decrypt with the region pad, because nothing has
    /// derived the session key yet. The brute force only needs its raw bytes.
    fn carrier_body() -> Vec<u8> {
        Message {
            fields: vec![Field::new(4, Value::LengthDelimited(vec![0x33; 160]))],
        }
        .encode()
    }

    fn game_data() -> GameData {
        // zzz-scan -> crates -> rust -> repository root.
        let assets = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../assets");
        GameData::load(&assets).expect("the committed assets must load")
    }

    /// Build the two packets of a login handshake encrypted with `build_pad`, then
    /// scan them with `scan_pad`, exactly as a replay would.
    ///
    /// The two pads are separate on purpose: a region mismatch means the wire was
    /// encrypted with one pad and is being read with another, and building both
    /// sides with the same pad (the obvious mistake) hides exactly that.
    fn run_handshake<'a>(
        data: &'a GameData,
        build_pad: &XorPad,
        scan_pad: XorPad,
    ) -> (Vec<DecodeEvent>, Scanner<'a>) {
        let token_plain = {
            let ciphertext = rsa::encrypt_block(&SERVER_RAND_KEY.to_le_bytes()).unwrap();
            let mut message = Message::default();
            message.fields.push(Field::new(
                9,
                Value::LengthDelimited(b64_encode(&ciphertext).into_bytes()),
            ));
            message.encode()
        };
        let token_wire = xorpad::xor_bytes(&token_plain, build_pad.bytes());

        let session_key = SERVER_RAND_KEY ^ client_rand_key(seed_from_unix_seconds(LOGIN_TIME));
        let session_pad = xorpad::session(session_key);
        let carrier_wire = xorpad::xor_bytes(&carrier_body(), &session_pad);
        let sync_wire = xorpad::xor_bytes(&sync_body(), &session_pad);

        let mut scanner = Scanner::new(scan_pad, &data.datamine, &data.nap);
        let mut events = Vec::new();
        let packets = [
            (data.datamine.cmd_player_get_token_sc_rsp as u16, token_wire),
            (data.datamine.cmd_player_sync_sc_notify as u16, carrier_wire),
            (data.datamine.cmd_player_sync_sc_notify as u16, sync_wire),
        ];
        for (sn, (command_id, body)) in packets.into_iter().enumerate() {
            events.extend(scanner.feed(
                &segment(sn as u32, &message(command_id, &body)),
                Direction::Incoming,
                LOGIN_TIME,
            ));
        }
        (events, scanner)
    }

    #[test]
    fn decodes_a_synthetic_login_handshake() {
        let data = game_data();
        let (_, seed_text) = data.datamine.xor_seeds.iter().next().expect("a region");
        let seed = u64::from_str_radix(seed_text, 16).expect("hex seed");
        let pad = XorPad::for_region(seed);
        let (events, scanner) = run_handshake(&data, &pad, pad.clone());

        assert_eq!(
            events.first(),
            Some(&DecodeEvent::ServerRandKey {
                key: SERVER_RAND_KEY
            }),
            "events were {events:?}"
        );
        assert!(
            matches!(events.get(1), Some(DecodeEvent::SessionKey { found }) if found.delta == 0),
            "events were {events:?}"
        );
        // The carrier is decrypted *before* the key it carries is derived, exactly
        // as the original does, so its body is read with the region pad and comes
        // out as noise. Its content is spent on the handshake; the messages after
        // it are the ones that decode.
        assert!(
            matches!(events.get(2), Some(DecodeEvent::ProtoFailed { bytes, .. }) if *bytes == carrier_body().len()),
            "events were {events:?}"
        );
        assert!(
            matches!(events.get(3), Some(DecodeEvent::Message { bytes, .. }) if *bytes == sync_body().len()),
            "events were {events:?}"
        );
        assert!(scanner.decoded_anything());

        assert!(scanner.handshake_complete());
        assert_eq!(scanner.session().session_key.unwrap(), {
            SERVER_RAND_KEY ^ client_rand_key(seed_from_unix_seconds(LOGIN_TIME))
        });
        assert_eq!(
            scanner.stats().decoded,
            1,
            "only the sync message decodes; the token response returns early"
        );
        assert_eq!(scanner.kcp_stats().conv_resets, 0);
    }

    #[test]
    fn a_wrong_region_seed_decodes_nothing() {
        // This is what makes region detection work: with the wrong pad the token
        // response decrypts to noise, so no scanner using it ever gets far.
        let data = game_data();
        let (_, seed_text) = data.datamine.xor_seeds.iter().next().expect("a region");
        let seed = u64::from_str_radix(seed_text, 16).expect("hex seed");
        let right_pad = XorPad::for_region(seed);

        let (right_events, right) = run_handshake(&data, &right_pad, right_pad.clone());
        let (wrong_events, wrong) =
            run_handshake(&data, &right_pad, XorPad::for_region(seed ^ 0xDEAD_BEEF));

        assert!(right.handshake_complete());
        assert_eq!(right.stats().decoded, 1, "events were {right_events:?}");
        assert_eq!(wrong.stats().decoded, 0, "events were {wrong_events:?}");
        assert!(
            !wrong_events.iter().any(
                |e| matches!(e, DecodeEvent::ServerRandKey { key } if *key == SERVER_RAND_KEY)
            ),
            "a wrong pad must not recover the real key: {wrong_events:?}"
        );
        assert!(right_events.len() > wrong_events.len());
    }

    /// The wiring `pcap.hpp` does inline: a message that decodes is handed to the
    /// extraction pass before the next packet is read.
    #[test]
    fn a_decoded_sync_reaches_the_inventory() {
        let data = game_data();
        // No handshake is needed here: extraction runs on whatever decodes, and
        // the sync message decrypts with whichever pad is currently in use.
        let pad = XorPad::for_region(1);
        let mut scanner = Scanner::new(pad.clone(), &data.datamine, &data.nap);
        let command_id = data.datamine.cmd_player_sync_sc_notify as u16;

        let item_sync = Message {
            fields: vec![
                Field::new(
                    data.datamine.sync_item_data.equips,
                    Value::LengthDelimited(
                        Message {
                            fields: vec![
                                Field::new(data.datamine.disc_info.uid, Value::Varint(15916)),
                                Field::new(data.datamine.disc_info.id, Value::Varint(31244)),
                                Field::new(data.datamine.disc_info.level, Value::Varint(15)),
                            ],
                        }
                        .encode(),
                    ),
                ),
                Field::new(
                    data.datamine.sync_item_data.deleted_equips,
                    Value::LengthDelimited(vec![0x92, 0xA1, 0x01]), // 4242, packed
                ),
            ],
        };
        let mut body_message = Message {
            fields: vec![Field::new(
                data.datamine.sync_item_data.item_sync,
                Value::LengthDelimited(item_sync.encode()),
            )],
        };
        // nap.json obfuscates selected scalar values, so put the fixture into the
        // form it travels in. The decoder's pass is the inverse of this, which is
        // why the assertions below see the numbers written above.
        xor_proto_fields(
            &mut body_message,
            data.nap.entry_by_cmd(command_id),
            &data.nap,
        );

        let wire = xorpad::xor_bytes(&body_message.encode(), pad.bytes());
        let events = scanner.feed(
            &segment(0, &message(command_id, &wire)),
            Direction::Incoming,
            LOGIN_TIME,
        );

        assert!(
            events
                .iter()
                .any(|event| matches!(event, DecodeEvent::Message { .. })),
            "events were {events:?}"
        );
        assert_eq!(scanner.inventory().discs.len(), 1);
        assert_eq!(scanner.inventory().discs[0].uid, 15916);
        assert_eq!(scanner.inventory().discs[0].level, 15);
        assert_eq!(scanner.inventory().discs[0].set_id(), 31200);
        assert_eq!(scanner.inventory().discs[0].rarity(), 5);
        assert_eq!(scanner.extract().player_syncs, 1);
        assert_eq!(scanner.extract().sync_upserts, 1);
        // The removal names a uid that was never seen, so nothing is counted.
        assert_eq!(scanner.extract().sync_removals, 0);
    }

    #[test]
    fn a_message_shorter_than_its_header_declares_is_clamped() {
        let data = game_data();
        let mut scanner = Scanner::new(XorPad::for_region(1), &data.datamine, &data.nap);
        // Header claims 1000 bytes of body; only 3 are present.
        let mut bytes = message(7, &[1, 2, 3]);
        bytes[8..12].copy_from_slice(&1000u32.to_le_bytes());
        let events = scanner.feed(&segment(0, &bytes), Direction::Incoming, LOGIN_TIME);

        let carried = events
            .iter()
            .find_map(|event| match event {
                DecodeEvent::Message { bytes, .. } | DecodeEvent::ProtoFailed { bytes, .. } => {
                    Some(*bytes)
                }
                _ => None,
            })
            .expect("the message is reported, not dropped");
        assert_eq!(
            carried, 3,
            "the body is the bytes present, not the declared 1000"
        );
        assert_eq!(scanner.stats().messages, 1);
    }
}
