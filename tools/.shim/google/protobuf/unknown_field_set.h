#pragma once

// A stand-in for protobuf's `UnknownFieldSet`, for hosts that cannot build the
// real library (no vcpkg, no OpenSSL, no protobuf — this repository's checkout
// on the machine the parity harness was written on).
//
// The project's own headers include protobuf for exactly one type: the
// schema-free `UnknownFieldSet` that carries a decoded message body. Everything
// it asks of it is the small surface below, and the wire format it parses is
// fifteen lines of specification, so the shim implements it rather than
// declaring stubs that would compile and then misbehave if anyone called them.
//
// Two deliberate gaps, both irrelevant to the export this harness compares:
//
//   * Groups (wire types 3 and 4) are rejected rather than skipped. Real
//     protobuf decodes them; the game's messages do not use them.
//   * `serialized_size`, reflection and the generated-message API are absent.
//
// This is a shim for a *third-party* library, and the point of saying so is
// that nothing above it is a shim: `data::*`, `SyncApplier` and
// `Serialization::Zod::*` are the project's own code, compiled unchanged.

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace google {
	namespace protobuf {

		class UnknownField {
		public:
			enum Type {
				TYPE_VARINT = 0,
				TYPE_FIXED64 = 1,
				TYPE_LENGTH_DELIMITED = 2,
				TYPE_GROUP = 3,
				TYPE_FIXED32 = 5,
			};

			[[nodiscard]] int number() const { return number_; }
			[[nodiscard]] Type type() const { return type_; }
			[[nodiscard]] uint64_t varint() const { return value_; }
			[[nodiscard]] uint32_t fixed32() const { return static_cast<uint32_t>(value_); }
			[[nodiscard]] uint64_t fixed64() const { return value_; }
			[[nodiscard]] const std::string &length_delimited() const { return bytes_; }

			void set_number(int number) { number_ = number; }
			void set_type(Type type) { type_ = type; }
			void set_varint(uint64_t value) { value_ = value; }
			void set_fixed32(uint32_t value) { value_ = value; }
			void set_fixed64(uint64_t value) { value_ = value; }
			void set_length_delimited(std::string value) { bytes_ = std::move(value); }

		private:
			int number_ = 0;
			Type type_ = TYPE_VARINT;
			uint64_t value_ = 0;
			std::string bytes_;
		};

		class UnknownFieldSet {
		public:
			bool ParseFromArray(const void *data, int size);

			// Takes a `string_view`, not a `const std::string&`: the project's own
			// code passes the result of `length_delimited()` straight in, and the
			// real header's `ConstStringParam` accepts a view.
			bool ParseFromString(std::string_view data) {
				return ParseFromArray(data.data(), static_cast<int>(data.size()));
			}

			[[nodiscard]] int field_count() const { return static_cast<int>(fields_.size()); }

			[[nodiscard]] const UnknownField &field(int index) const {
				return fields_[static_cast<size_t>(index)];
			}

			UnknownField *mutable_field(int index) {
				return &fields_[static_cast<size_t>(index)];
			}

			bool SerializeToString(std::string *out) const;

			void Clear() { fields_.clear(); }

		private:
			std::vector<UnknownField> fields_;
		};

		inline bool UnknownFieldSet::ParseFromArray(const void *data, int size) {
			fields_.clear();
			if (size < 0) return false;
			const auto *bytes = static_cast<const uint8_t *>(data);
			const size_t len = static_cast<size_t>(size);
			size_t pos = 0;

			// Reads a base-128 varint, or fails if it runs off the end.
			const auto read_varint = [&](uint64_t &out) {
				out = 0;
				unsigned shift = 0;
				while (pos < len && shift < 64) {
					const uint8_t byte = bytes[pos++];
					out |= static_cast<uint64_t>(byte & 0x7F) << shift;
					if (!(byte & 0x80)) return true;
					shift += 7;
				}
				return false;
			};

			while (pos < len) {
				uint64_t tag = 0;
				if (!read_varint(tag)) return false;
				const auto number = static_cast<int>(tag >> 3);
				const auto wire = static_cast<int>(tag & 0x7);

				UnknownField field;
				field.set_number(number);
				if (wire == 0) {
					uint64_t value = 0;
					if (!read_varint(value)) return false;
					field.set_type(UnknownField::TYPE_VARINT);
					field.set_varint(value);
				} else if (wire == 1) {
					if (pos + 8 > len) return false;
					uint64_t value = 0;
					for (int byte = 0; byte < 8; byte++) value |= static_cast<uint64_t>(bytes[pos++]) << (8 * byte);
					field.set_type(UnknownField::TYPE_FIXED64);
					field.set_fixed64(value);
				} else if (wire == 2) {
					uint64_t length = 0;
					if (!read_varint(length)) return false;
					if (pos + length > len) return false;
					field.set_type(UnknownField::TYPE_LENGTH_DELIMITED);
					field.set_length_delimited(std::string{
						reinterpret_cast<const char *>(bytes + pos),
						static_cast<size_t>(length),
					});
					pos += static_cast<size_t>(length);
				} else if (wire == 5) {
					if (pos + 4 > len) return false;
					uint32_t value = 0;
					for (int byte = 0; byte < 4; byte++) value |= static_cast<uint32_t>(bytes[pos++]) << (8 * byte);
					field.set_type(UnknownField::TYPE_FIXED32);
					field.set_fixed32(value);
				} else {
					return false;
				}
				fields_.push_back(std::move(field));
			}
			return true;
		}

		inline bool UnknownFieldSet::SerializeToString(std::string *out) const {
			out->clear();
			const auto write_varint = [&](uint64_t value) {
				while (true) {
					const auto byte = static_cast<uint8_t>(value & 0x7F);
					value >>= 7;
					if (value == 0) {
						out->push_back(static_cast<char>(byte));
						return;
					}
					out->push_back(static_cast<char>(byte | 0x80));
				}
			};

			for (const auto &field: fields_) {
				write_varint((static_cast<uint64_t>(field.number()) << 3) | static_cast<uint64_t>(field.type()));
				switch (field.type()) {
					case UnknownField::TYPE_VARINT:
						write_varint(field.varint());
						break;
					case UnknownField::TYPE_FIXED32:
						for (int byte = 0; byte < 4; byte++) out->push_back(static_cast<char>((field.fixed32() >> (8 * byte)) & 0xFF));
						break;
					case UnknownField::TYPE_FIXED64:
						for (int byte = 0; byte < 8; byte++) out->push_back(static_cast<char>((field.fixed64() >> (8 * byte)) & 0xFF));
						break;
					case UnknownField::TYPE_LENGTH_DELIMITED:
						write_varint(field.length_delimited().size());
						out->append(field.length_delimited());
						break;
					default:
						return false;
				}
			}
			return true;
		}
	}// namespace protobuf
}// namespace google
