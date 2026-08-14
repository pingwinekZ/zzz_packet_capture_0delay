// Self-test for the WebSocket live-export server (Phase 1).
// Exercises the RFC 6455 handshake (including the RFC 6455 example key),
// initial snapshot push, broadcast frames, masked client frames, ping/pong,
// close handshake and client lifecycle:
//   zzz_ws_test

#include "websocket/websocketServer.hpp"

#include <array>
#include <cstdint>
#include <print>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

namespace {
	constexpr const char *rfcKey = "dGhlIHNhbXBsZSBub25jZQ==";
	constexpr const char *rfcAccept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

	struct TestClient {
		asio::io_context io;
		asio::ip::tcp::socket socket{io};

		explicit TestClient(uint16_t port) {
			socket.connect(asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), port));
		}
		void sendAll(std::string_view data) {
			asio::write(socket, asio::buffer(data));
		}
		std::string readUntilHeaders() {
			asio::streambuf buf;
			asio::read_until(socket, buf, "\r\n\r\n");
			return std::string(std::istreambuf_iterator<char>(&buf), std::istreambuf_iterator<char>());
		}
		void handshake() {
			std::string request =
				"GET /ws HTTP/1.1\r\n"
				"Host: 127.0.0.1\r\n"
				"Upgrade: websocket\r\n"
				"Connection: Upgrade\r\n"
				"Sec-WebSocket-Key: " + std::string(rfcKey) + "\r\n"
				"Sec-WebSocket-Version: 13\r\n\r\n";
			sendAll(request);
			auto headers = readUntilHeaders();
			if (headers.find("101") == std::string::npos) {
				throw std::runtime_error("handshake failed: " + headers);
			}
			if (headers.find(rfcAccept) == std::string::npos) {
				throw std::runtime_error("unexpected Sec-WebSocket-Accept in: " + headers);
			}
		}
		void sendFrame(uint8_t opcode, std::string_view payload, bool masked = true) {
			std::string frame;
			frame.push_back(static_cast<char>(0x80 | opcode));
			uint64_t len = payload.size();
			uint8_t maskBit = masked ? 0x80 : 0;
			if (len < 126) {
				frame.push_back(static_cast<char>(len | maskBit));
			} else if (len <= 0xFFFF) {
				frame.push_back(static_cast<char>(126 | maskBit));
				frame.push_back(static_cast<char>((len >> 8) & 0xFF));
				frame.push_back(static_cast<char>(len & 0xFF));
			} else {
				frame.push_back(static_cast<char>(127 | maskBit));
				for (int i = 7; i >= 0; --i) frame.push_back(static_cast<char>((len >> (i * 8)) & 0xFF));
			}
			if (masked) {
				const uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};
				frame.append(reinterpret_cast<const char *>(mask), 4);
				for (size_t i = 0; i < payload.size(); ++i) {
					frame.push_back(static_cast<char>(payload[i] ^ mask[i % 4]));
				}
			} else {
				frame.append(payload);
			}
			sendAll(frame);
		}
		std::pair<uint8_t, std::string> readFrame() {
			std::array<uint8_t, 2> head{};
			asio::read(socket, asio::buffer(head));
			uint8_t opcode = head[0] & 0x0F;
			uint64_t len = head[1] & 0x7F;
			if (head[1] & 0x80) throw std::runtime_error("server frames must not be masked");
			if (len == 126) {
				std::array<uint8_t, 2> ext{};
				asio::read(socket, asio::buffer(ext));
				len = (static_cast<uint64_t>(ext[0]) << 8) | ext[1];
			} else if (len == 127) {
				std::array<uint8_t, 8> ext{};
				asio::read(socket, asio::buffer(ext));
				len = 0;
				for (uint8_t byte: ext) len = (len << 8) | byte;
			}
			std::string payload(static_cast<size_t>(len), '\0');
			asio::read(socket, asio::buffer(payload));
			return {opcode, payload};
		}
	};
}// namespace

int main() {
	bool ok = true;
	auto check = [&](bool cond, const char *what) {
		std::println("{} {}", cond ? "[PASS]" : "[FAIL]", what);
		ok = ok && cond;
	};

	constexpr uint16_t port = 23456;
	websocket::Server server;
	server.onSnapshotRequested = []() {
		return std::string{"{\"format\":\"ZOD\",\"snapshot\":true}"};
	};

	check(server.start(port), "server start");
	check(server.clientCount() == 0, "no clients initially");

	{
		TestClient client(port);
		client.handshake();
		check(true, "handshake (RFC 6455 example key/accept)");

		for (int i = 0; i < 100 && server.clientCount() != 1; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
		check(server.clientCount() == 1, "client registered");

		auto [op1, snap] = client.readFrame();
		check(op1 == 1 && snap == "{\"format\":\"ZOD\",\"snapshot\":true}", "initial snapshot pushed on connect");

		server.broadcastText("hello world");
		auto [op2, hello] = client.readFrame();
		check(op2 == 1 && hello == "hello world", "broadcast frame received");

		client.sendFrame(1, "ignored text");
		server.broadcastText("after client text");
		auto [op3, after] = client.readFrame();
		check(op3 == 1 && after == "after client text", "server survived masked text frame");

		client.sendFrame(0x9, "p");
		auto [op4, pong] = client.readFrame();
		check(op4 == 0xA && pong == "p", "ping answered with pong");

		client.sendFrame(0x8, "");
		auto [op5, close] = client.readFrame();
		check(op5 == 0x8, "close request answered with close frame");

		for (int i = 0; i < 100 && server.clientCount() != 0; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
		check(server.clientCount() == 0, "client deregistered after close");
	}

	{
		TestClient client(port);
		client.handshake();
		for (int i = 0; i < 100 && server.clientCount() != 1; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
		check(server.clientCount() == 1, "second client connected");

		server.stop();
		check(server.clientCount() == 0, "stop() disconnects clients");

		try {
			asio::error_code ec;
			std::array<uint8_t, 2> head{};
			asio::read(client.socket, asio::buffer(head), ec);
			check(static_cast<bool>(ec), "client socket closed after stop()");
		} catch (...) {
			check(true, "client socket closed after stop()");
		}
	}

	check(server.start(port), "restart after stop (reuse_address)");
	{
		TestClient client(port);
		client.handshake();
		auto [op, snap] = client.readFrame();
		check(op == 1 && snap == "{\"format\":\"ZOD\",\"snapshot\":true}", "restarted server serves snapshots");
	}
	server.stop();

	std::println("{}", ok ? "TEST PASSED" : "TEST FAILED");
	return ok ? 0 : 1;
}