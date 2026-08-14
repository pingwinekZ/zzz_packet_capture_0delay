#pragma once

#include "../data/agent.hpp"
#include "../data/disc.hpp"
#include "../data/engine.hpp"
#include "../serialization/datamine.hpp"
#include "google/protobuf/unknown_field_set.h"
#include <algorithm>
#include <cstdint>
#include <vector>


namespace pcap {
	struct SyncResult {
		bool changed = false;
		uint32_t upserts = 0;
		uint32_t removals = 0;
	};

	class SyncApplier {
	public:
		SyncApplier(
			std::vector<data::DiscInfo> &discs,
			std::vector<data::WeaponInfo> &engines,
			std::vector<data::AgentInfo> &agents
		) : discs_(discs), engines_(engines), agents_(agents) {}

		// PlayerSyncScNotify: avatarSync (9) + itemSync (15) submessages
		[[nodiscard]] SyncResult applyPlayerSync(const google::protobuf::UnknownFieldSet &ufs) {
			SyncResult out;
			auto &datamine = serialization::Datamine::get();
			for (int i = 0; i < ufs.field_count(); ++i) {
				const auto &f = ufs.field(i);
				if (f.type() != google::protobuf::UnknownField::TYPE_LENGTH_DELIMITED) continue;

				if (f.number() == datamine.syncAvatarData.avatarSync) {
					google::protobuf::UnknownFieldSet nested;
					if (nested.ParseFromString(f.length_delimited())) {
						auto result = applyAvatarSync(nested);
						out.changed |= result.changed;
						out.upserts += result.upserts;
						out.removals += result.removals;
					}
				} else if (f.number() == datamine.syncItemData.itemSync) {
					google::protobuf::UnknownFieldSet nested;
					if (nested.ParseFromString(f.length_delimited())) {
						auto result = applyItemSync(nested);
						out.changed |= result.changed;
						out.upserts += result.upserts;
						out.removals += result.removals;
					}
				}
			}
			return out;
		}

		// DismantleEquipCsReq (5185): removed equip uids at repeated packed field uids (2)
		[[nodiscard]] SyncResult applyEquipDismantle(const google::protobuf::UnknownFieldSet &ufs) {
			SyncResult out;
			auto &datamine = serialization::Datamine::get();
			std::vector<uint32_t> uids;
			for (int i = 0; i < ufs.field_count(); ++i) {
				const auto &f = ufs.field(i);
				if (f.number() == datamine.equipDismantle.uid || f.number() == datamine.equipDismantle.uids) {
					collectUints(f, uids);
				}
			}
			for (const auto uid: uids) {
				if (removeDisc(uid) | removeEngine(uid)) {
					out.changed = true;
					++out.removals;
				}
			}
			return out;
		}

		bool upsertDisc(const data::DiscInfo &disc) {
			auto it = std::find_if(discs_.begin(), discs_.end(), [&disc](const auto &d) { return d.uid == disc.uid; });
			if (it != discs_.end()) {
				*it = disc;
			} else {
				discs_.push_back(disc);
			}
			return true;
		}

		bool upsertEngine(const data::WeaponInfo &weapon) {
			auto it = std::find_if(engines_.begin(), engines_.end(), [&weapon](const auto &w) { return w.uid == weapon.uid; });
			if (it != engines_.end()) {
				*it = weapon;
			} else {
				engines_.push_back(weapon);
			}
			return true;
		}

		bool upsertAgent(const data::AgentInfo &agent) {
			auto it = std::find_if(agents_.begin(), agents_.end(), [&agent](const auto &a) { return a.id == agent.id; });
			if (it != agents_.end()) {
				*it = agent;
			} else {
				agents_.push_back(agent);
			}
			return true;
		}

	private:
		std::vector<data::DiscInfo> &discs_;
		std::vector<data::WeaponInfo> &engines_;
		std::vector<data::AgentInfo> &agents_;

		static void collectUints(const google::protobuf::UnknownField &f, std::vector<uint32_t> &out) {
			if (f.type() == google::protobuf::UnknownField::TYPE_VARINT) {
				out.push_back(static_cast<uint32_t>(f.varint()));
				return;
			}
			if (f.type() != google::protobuf::UnknownField::TYPE_LENGTH_DELIMITED) return;
			auto data = f.length_delimited();
			size_t pos = 0;
			while (pos < data.size()) {
				uint64_t value = 0;
				unsigned shift = 0;
				bool done = false;
				while (pos < data.size() && shift < 64) {
					const auto b = static_cast<uint8_t>(data[pos++]);
					value |= static_cast<uint64_t>(b & 0x7F) << shift;
					if (!(b & 0x80)) {
						done = true;
						break;
					}
					shift += 7;
				}
				if (!done) break;
				out.push_back(static_cast<uint32_t>(value));
			}
		}

		[[nodiscard]] SyncResult applyAvatarSync(const google::protobuf::UnknownFieldSet &ufs) {
			SyncResult out;
			auto &datamine = serialization::Datamine::get();
			for (int i = 0; i < ufs.field_count(); ++i) {
				const auto &f = ufs.field(i);
				if (f.number() == datamine.syncAvatarData.avatars && f.type() == google::protobuf::UnknownField::TYPE_LENGTH_DELIMITED) {
					google::protobuf::UnknownFieldSet nested;
					if (nested.ParseFromString(f.length_delimited())) {
						upsertAgent(data::AgentInfo::fromUFS(nested));
						out.changed = true;
						++out.upserts;
					}
				} else if (f.number() == datamine.syncAvatarData.dels) {
					std::vector<uint32_t> ids;
					collectUints(f, ids);
					for (const auto id: ids) {
						if (removeAgent(id)) {
							out.changed = true;
							++out.removals;
						}
					}
				}
			}
			return out;
		}

		[[nodiscard]] SyncResult applyItemSync(const google::protobuf::UnknownFieldSet &ufs) {
			SyncResult out;
			auto &datamine = serialization::Datamine::get();
			for (int i = 0; i < ufs.field_count(); ++i) {
				const auto &f = ufs.field(i);
				if (f.type() != google::protobuf::UnknownField::TYPE_LENGTH_DELIMITED) continue;

				if (f.number() == datamine.syncItemData.equips) {
					google::protobuf::UnknownFieldSet nested;
					if (nested.ParseFromString(f.length_delimited())) {
						upsertDisc(data::DiscInfo::fromUFS(nested));
						out.changed = true;
						++out.upserts;
					}
				} else if (f.number() == datamine.syncItemData.weapons) {
					google::protobuf::UnknownFieldSet nested;
					if (nested.ParseFromString(f.length_delimited())) {
						upsertEngine(data::WeaponInfo::fromUFS(nested));
						out.changed = true;
						++out.upserts;
					}
				} else if (f.number() == datamine.syncItemData.deletedEquips) {
					std::vector<uint32_t> uids;
					collectUints(f, uids);
					for (const auto uid: uids) {
						if (removeDisc(uid)) {
							out.changed = true;
							++out.removals;
						}
					}
				}
			}
			return out;
		}

		bool removeDisc(uint32_t uid) {
			auto it = std::find_if(discs_.begin(), discs_.end(), [uid](const auto &d) { return d.uid == uid; });
			if (it == discs_.end()) return false;
			discs_.erase(it);
			return true;
		}

		bool removeEngine(uint32_t uid) {
			auto it = std::find_if(engines_.begin(), engines_.end(), [uid](const auto &w) { return w.uid == uid; });
			if (it == engines_.end()) return false;
			engines_.erase(it);
			return true;
		}

		bool removeAgent(uint32_t id) {
			auto it = std::find_if(agents_.begin(), agents_.end(), [id](const auto &a) { return a.id == id; });
			if (it == agents_.end()) return false;
			agents_.erase(it);
			return true;
		}
	};
}// namespace pcap