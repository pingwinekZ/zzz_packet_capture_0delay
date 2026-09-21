#pragma once

// The part of `src/pcap/pcap.hpp` that `Serialization::Zod::IZOD::fromPcap`
// reads: the three inventories, and nothing else.
//
// The real header pulls in the capture device, the KCP reassembler and the
// session handshake, which between them need pcap++, protobuf and OpenSSL. None
// of those are available here, and none of them touch the export, so this shim
// supplies the three vectors. `IZOD.hpp` includes `"pcap/pcap.hpp"`, which
// resolves to this file because the harness puts `tools/.shim` first on the
// include path — the real `src/pcap/pcap.hpp` is still the definition the
// project builds against.
//
// The members are named and typed exactly as the real ones, so the only way
// this file can affect the comparison is by lying about them, which the parity
// test would catch as an empty or reordered export.

#include "data/agent.hpp"
#include "data/disc.hpp"
#include "data/engine.hpp"
#include <vector>


struct Pcap {
	std::vector<data::DiscInfo> discs;
	std::vector<data::WeaponInfo> engines;
	std::vector<data::AgentInfo> agents;
};
