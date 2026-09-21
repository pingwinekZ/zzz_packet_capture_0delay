// Prints what glaze actually does when it serializes, which is not quite what
// JSON allows.
//
//   The ZOD export is parsed by an optimizer that eats the reference's output,
//   so the Rust port has to emit the same *bytes*, not merely equivalent JSON.
//   That makes glaze's escaping rules part of the specification, and they are
//   narrower than the spec's: only `"`, `\`, `\b`, `\t`, `\n`, `\f` and `\r` are
//   escaped, and every other control byte is written raw — which produces
//   invalid JSON for a name containing `0x01` and is nonetheless what has to be
//   reproduced. `rust/crates/zzz-export/src/json.rs` does reproduce it, and this
//   program is how that decision can be rechecked.
//
// Run it after changing the glaze version the project builds against: if the
// escape set moved, `json.rs`'s unit tests will still pass (they assert the
// behaviour, not the dependency) but the *reference* output would have changed,
// which is a difference the export parity goldens would show up as a mismatch
// only if a name happens to contain a control byte.
//
// Build and run (developer command prompt; see `cpp_export.cpp` for why the
// environment is set by hand):
//
//   cl /nologo /std:c++latest /EHsc /W3 /O2 ^
//      /I tools\.glaze\glaze-8.4.0\include tools\cpp_glaze_probe.cpp
//   cpp_glaze_probe.exe

#include <cstdint>
#include <cstdio>
#include <glaze/glaze.hpp>
#include <string>

// At namespace scope, not in an anonymous namespace: glaze reflects a type by
// naming it, and a type with internal linkage has no name to reflect.
struct OneString {
	std::string text;
};

struct Numbers {
	uint8_t small = 255;
	uint32_t large = 4294967295u;
	bool flag = true;
};

namespace {

	void show_string(const char *label, const std::string &text) {
		auto json = glz::write_json(OneString{text});
		if (!json) {
			std::printf("%-12s <failed to serialize>\n", label);
			return;
		}
		std::printf("%-12s %s\n", label, json->c_str());
	}

}// namespace

int main() {
	std::printf("Every byte below 0x20, and the two the JSON spec short-escapes:\n");
	for (int byte = 0; byte < 0x20; byte++) {
		std::string text = "a";
		text.push_back(static_cast<char>(byte));
		text.push_back('b');
		char label[16];
		std::snprintf(label, sizeof(label), "0x%02X", byte);
		show_string(label, text);
	}
	show_string("quote", "a\"b");
	show_string("backslash", "a\\b");
	// Not escaped, and worth knowing: a forward slash needs no escape in JSON,
	// but writers that fear `</script>` escape it anyway.
	show_string("slash", "a/b");
	show_string("DEL", std::string("a\x7Fz"));
	// Passed through as UTF-8 bytes, not as \u escapes.
	show_string("utf8", "Anby \xE9\x9B\xAA\xE8\xA1\xA3");
	show_string("empty", "");

	std::printf("\nWidths, which the export's uint8_t fields and uint32_t counts depend on:\n");
	if (auto json = glz::write_json(Numbers{})) {
		std::printf("%-12s %s\n", "bounds", json->c_str());
	}
	return 0;
}
