#include "IAgent.hpp"

#include "../../util/strings.hpp"

Serialization::Zod::IAgent Serialization::Zod::IAgent::fromInstance(const data::AgentInfo &agent, const std::unordered_map<uint32_t, const data::WeaponInfo *> &engines, bool exportEngines) {
	std::optional<std::string> wengineKey;
	std::optional<uint8_t> wenginePhase;
	if (exportEngines) {
		if (auto it = engines.find(agent.weaponUid); it != engines.end()) {
			wengineKey = util::strings::toZodKey(std::string{it->second->name()});
			wenginePhase = static_cast<uint8_t>(it->second->phase);
		} else {
			wengineKey = "";
			wenginePhase = 1;
		}
	}

	return {
		.key = util::strings::toZodKey(std::string{agent.name()}),
		.level = static_cast<uint8_t>(agent.level),
		.mindscape = static_cast<uint8_t>(agent.mindscape),
		.promotion = static_cast<uint8_t>(agent.promotion - 1),
		.core = static_cast<uint8_t>(agent.skills.at(4).level - 1),
		.dodge = static_cast<uint8_t>(agent.skills.at(2).level),
		.basic = static_cast<uint8_t>(agent.skills.at(0).level),
		.chain = static_cast<uint8_t>(agent.skills.at(3).level),
		.special = static_cast<uint8_t>(agent.skills.at(1).level),
		.assist = static_cast<uint8_t>(agent.skills.at(5).level),
		.potential = 0,
		.wengineKey = std::move(wengineKey),
		.wenginePhase = wenginePhase,
	};
}