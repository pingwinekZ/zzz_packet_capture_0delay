// Runs the project's *own* ZOD export over an inventory and writes the JSON, so
// the Rust port can be compared against the reference byte for byte.
//
//   zzz-export is ported from `src/serialization/zod/`, and this harness
//   compiles that code — `IZOD::fromPcap`, `IAgent::fromInstance`,
//   `IDisc::fromInstance`, `IEngine::fromInstance` — together with the real
//   `data::*` model headers, the real `data::ExportSettings`, the real
//   `util::strings::toZodKey` and the real nanoka/datamine loaders, and lets
//   glaze serialize the result. Nothing between the input inventory and the
//   output bytes is reimplemented here.
//
// Build (a developer command prompt; the same manual environment as
// `cpp_parity.cpp`, because `vcvars64.bat` hangs under a Git Bash shell):
//
//   cl /nologo /std:c++latest /EHsc /W3 /O2 ^
//      /I tools\.shim /I src /I glt\include /I tools\.glaze\glaze-8.4.0\include ^
//      tools\cpp_export.cpp /Fe:tools\cpp_export.exe
//
// `tools/.shim` has to come first: it holds the stand-ins for the three
// libraries this host cannot build (`google/protobuf/unknown_field_set.h`,
// `pcap/pcap.hpp`) explained in their own headers.
//
// Run from the repository root, because the loaders read `assets/*.json`
// relative to the working directory:
//
//   tools\cpp_export.exe rust\testdata\parity\zod_inventory.json out.json [default|unfiltered]
//
// The output file is what `rust/crates/zzz-export/tests/cpp_export_parity.rs`
// asserts against.

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <fstream>
#include <iterator>
#include <print>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "glaze/glaze.hpp"
#include "serialization/zod/IZOD.hpp"

// The reference's export is four translation units; they are included here so
// that one `cl` invocation builds the whole thing and the standard headers the
// project relies on arriving transitively (notably `<format>` inside
// `IDisc.cpp`) are already in scope.
#include "serialization/zod/IAgent.cpp"
#include "serialization/zod/IDisc.cpp"
#include "serialization/zod/IEngine.cpp"
#include "serialization/zod/IZOD.cpp"

// glt declares `squi::Networking::get` and defines it in a translation unit this
// harness does not link. Nothing in the export fetches — the data files are on
// disk — but `NanokaData::shouldUpdate` probes the published manifest before it
// trusts the cache, so the symbol has to resolve. Failing the request is exactly
// what an offline C++ build does, and it leaves `assets/nanokaData.json`
// authoritative for both sides of the comparison.
namespace squi {
	Networking::Response Networking::get(const std::string &url, const std::unordered_map<std::string, std::string> &) {
		std::println("cpp_export: not fetching {}; the cached data files are used", url);
		Response response;
		response.success = false;
		response.error = "offline (this harness never fetches)";
		return response;
	}

	Networking::ResponseBody Networking::parseResponse(std::string_view) {
		return {};
	}
}// namespace squi

namespace {

	std::string read_file(const std::string &path) {
		std::ifstream file(path, std::ios::binary);
		if (!file.is_open()) {
			std::println("cannot open {}", path);
			std::exit(2);
		}
		return std::string{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
	}

	void write_file(const std::string &path, const std::string &body) {
		// Binary, so a byte-for-byte comparison is not at the mercy of the
		// platform's newline translation.
		std::ofstream file(path, std::ios::binary);
		if (!file.is_open()) {
			std::println("cannot write {}", path);
			std::exit(2);
		}
		file << body;
	}

}// namespace

int main(int argc, char **argv) {
	if (argc < 3) {
		std::println("usage: cpp_export <inventory.json> <out.json> [default|unfiltered]");
		return 2;
	}
	const std::string in_path = argv[1];
	const std::string out_path = argv[2];
	const std::string mode = argc > 3 ? argv[3] : "default";

	const std::string inventory = read_file(in_path);

	// `Pcap` is the shim's three vectors, named and typed as the real ones, so
	// glaze reads the inventory straight into the structure the export expects.
	Pcap pcap;
	if (auto read_error = glz::read<glz::opts{.error_on_unknown_keys = false}>(pcap, inventory)) {
		std::println("cannot read the inventory: {}", glz::format_error(read_error, inventory));
		return 2;
	}

	data::ExportSettings settings{};
	if (mode == "unfiltered") {
		settings.minDiscRarity = 0;
		settings.minEngineRarity = 0;
		settings.minAgentRarity = 0;
	} else if (mode != "default") {
		std::println("unknown mode {}", mode);
		return 2;
	}

	// The reference's own code, from here to the JSON.
	const auto zod = Serialization::Zod::IZOD::fromPcap(pcap, settings);

	std::string json;
	if (auto write_error = glz::write_json(zod, json)) {
		std::println("cannot serialize the export: {}", glz::format_error(write_error, json));
		return 2;
	}
	write_file(out_path, json);

	std::println(
		"{}: {} discs, {} engines, {} agents in -> {} characters, {} discs, {} wengines out ({} mode, {} bytes)",
		out_path,
		pcap.discs.size(),
		pcap.engines.size(),
		pcap.agents.size(),
		zod.characters ? zod.characters->size() : 0,
		zod.discs ? zod.discs->size() : 0,
		zod.wengines ? zod.wengines->size() : 0,
		mode,
		json.size()
	);
	return 0;
}
