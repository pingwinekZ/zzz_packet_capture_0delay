#pragma once

#include "../../data/agent.hpp"
#include "cstdint"
#include "data/engine.hpp"
#include "optional"
#include <string>
#include "unordered_map"


namespace Serialization::Zod {
	struct IAgent {
		std::string equippedEngine = ""; // Zenless optimizer bugs out and sets all skills to lvl 1 if you don't have this
		
		std::string key;
		uint8_t level;
		uint8_t mindscape;
		uint8_t promotion;
		
		uint8_t core;
		uint8_t dodge;
		uint8_t basic;
		uint8_t chain;
		uint8_t special;
		uint8_t assist;
		uint8_t potential;

		// nullopt = w-engine data not exported (engines category disabled), the
		// site then leaves the previously imported value untouched
		std::optional<std::string> wengineKey;
		std::optional<uint8_t> wenginePhase;

		std::string id = key;
		
		static IAgent fromInstance(const data::AgentInfo &agent, const std::unordered_map<uint32_t, const data::WeaponInfo *> &engines, bool exportEngines);
	};
}// namespace Serialization::Zod
