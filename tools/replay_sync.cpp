// Offline validation for the live-sync parser (Phase 4b).
// Replays recorded length-prefixed UFS dumps through pcap::SyncApplier:
//   zzz_sync_replay <login_discs.bin> <login_weapons.bin> <login_avatars.bin> <syncs.bin> <dismantles.bin>
// Expects to run with CWD containing assets/datamine.json.

#include "pcap/sync.hpp"
#include "google/protobuf/unknown_field_set.h"
#include "networking.hpp"
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <print>
#include <string>
#include <vector>

// Network is never used during replay (datamine.json is loaded from disk);
// provide a stub so the header-only template path links.
namespace squi {
	Networking::Response Networking::get(const std::string &, const std::unordered_map<std::string, std::string> &) {
		return Networking::Response{.success = false, .error = "network disabled in replay"};
	}
}


static std::vector<std::string> loadRecords(const char *path) {
	std::vector<std::string> out;
	std::ifstream file(path, std::ios::binary);
	if (!file.is_open()) {
		std::println(stderr, "failed to open {}", path);
		return out;
	}
	while (true) {
		uint32_t length = 0;
		file.read(reinterpret_cast<char *>(&length), sizeof(length));
		if (file.gcount() != sizeof(length)) break;
		std::string record(length, '\0');
		file.read(record.data(), length);
		if (file.gcount() != static_cast<std::streamsize>(length)) break;
		out.push_back(std::move(record));
	}
	return out;
}

static void applyLoginList(const std::string &path, uint32_t fieldNumber, const auto &upsert) {
	auto &datamine = serialization::Datamine::get();
	for (const auto &record: loadRecords(path.c_str())) {
		google::protobuf::UnknownFieldSet ufs;
		if (!ufs.ParseFromArray(record.data(), static_cast<int>(record.size()))) {
			std::println(stderr, "failed to parse record from {}", path);
			continue;
		}
		for (int i = 0; i < ufs.field_count(); ++i) {
			const auto &f = ufs.field(i);
			if (f.number() != fieldNumber || f.type() != google::protobuf::UnknownField::TYPE_LENGTH_DELIMITED) continue;
			google::protobuf::UnknownFieldSet nested;
			if (nested.ParseFromString(f.length_delimited())) upsert(nested);
		}
	}
}

int main(int argc, char **argv) {
	if (argc < 6) {
		std::println(stderr, "usage: {} <discs> <weapons> <avatars> <syncs> <dismantles>", argv[0]);
		return 2;
	}
	auto &datamine = serialization::Datamine::get();

	std::vector<data::DiscInfo> discs;
	std::vector<data::WeaponInfo> engines;
	std::vector<data::AgentInfo> agents;
	pcap::SyncApplier applier{discs, engines, agents};

	applyLoginList(argv[1], datamine.equipData.discs, [&](const google::protobuf::UnknownFieldSet &nested) {
		applier.upsertDisc(data::DiscInfo::fromUFS(nested));
	});
	applyLoginList(argv[2], datamine.weaponData.weapons, [&](const google::protobuf::UnknownFieldSet &nested) {
		applier.upsertEngine(data::WeaponInfo::fromUFS(nested));
	});
	applyLoginList(argv[3], datamine.agentData.agents, [&](const google::protobuf::UnknownFieldSet &nested) {
		applier.upsertAgent(data::AgentInfo::fromUFS(nested));
	});
	std::println("after login: {} discs, {} weapons, {} agents", discs.size(), engines.size(), agents.size());

	uint32_t upserts = 0;
	uint32_t removals = 0;
	for (const auto &record: loadRecords(argv[4])) {
		google::protobuf::UnknownFieldSet ufs;
		if (!ufs.ParseFromArray(record.data(), static_cast<int>(record.size()))) continue;
		auto result = applier.applyPlayerSync(ufs);
		upserts += result.upserts;
		removals += result.removals;
	}
	std::println("syncs: {} upserts, {} removals -> {} discs, {} weapons, {} agents", upserts, removals, discs.size(), engines.size(), agents.size());

	for (const auto &record: loadRecords(argv[5])) {
		google::protobuf::UnknownFieldSet ufs;
		if (!ufs.ParseFromArray(record.data(), static_cast<int>(record.size()))) continue;
		auto result = applier.applyEquipDismantle(ufs);
		removals += result.removals;
	}
	std::println("after dismantle: {} discs, {} weapons, {} agents", discs.size(), engines.size(), agents.size());

	bool ok = true;
	auto hasDisc = [&](uint32_t uid) {
		return std::any_of(discs.begin(), discs.end(), [uid](const auto &d) { return d.uid == uid; });
	};
	auto hasEngine = [&](uint32_t uid) {
		return std::any_of(engines.begin(), engines.end(), [uid](const auto &w) { return w.uid == uid; });
	};
	auto hasAgent = [&](uint32_t id) {
		return std::any_of(agents.begin(), agents.end(), [id](const auto &a) { return a.id == id; });
	};

	if (hasDisc(2960)) { ok = false; std::println("FAIL: dismantled disc 2960 still present"); }
	if (!hasDisc(15570)) { ok = false; std::println("FAIL: Feathered Fate 15570 missing"); }
	if (!hasEngine(14911)) { ok = false; std::println("FAIL: Boisterous Echoes 14911 missing"); }
	if (!hasEngine(17)) { ok = false; std::println("FAIL: Weeping Gemini 17 missing"); }
	if (!hasAgent(1581)) { ok = false; std::println("FAIL: avatar 1581 missing"); }
	if (ok) {
		for (const auto &a: agents) {
			if (a.id == 1581 && a.weaponUid != 14911) {
				ok = false;
				std::println("FAIL: avatar 1581 weaponUid {} != 14911", a.weaponUid);
			}
		}
	}
	for (const auto &d: discs) {
		if (d.uid == 2960) { ok = false; std::println("FAIL: duplicate/leftover disc 2960"); }
	}

	std::println("{}", ok ? "TEST PASSED" : "TEST FAILED");
	return ok ? 0 : 1;
}