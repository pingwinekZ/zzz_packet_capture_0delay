#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include "asio.hpp"
#include "openssl/evp.h"
#include "openssl/sha.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cctype>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <print>
#include <string>
#include <string_view>
#include <thread>
#include <vector>


namespace websocket {
	// Minimal RFC 6455 WebSocket server (server side, text frames only).
	//
	// Threading model:
	//  - A single accept thread runs the asio io_context: accepts connections,
	//    completes the HTTP upgrade handshake and parses inbound frames.
	//  - Each client has its own sender thread draining an outbox queue, so the
	//    capture thread (the one calling broadcastText) never blocks on I/O.
	class Server {
	public:
		// Called on the io thread when a client connects and no snapshot has been
		// broadcast yet, to produce the initial payload. Returns raw JSON text.
		std::function<std::string()> onSnapshotRequested;

		~Server() {
			stop();
		}

		// Binds 127.0.0.1:port and starts accepting. Returns false on failure.
		bool start(uint16_t port = 23313);
		// Stops the server and disconnects all clients. Safe to call from any thread.
		void stop();
		// Queues a text frame for every connected client. Never blocks.
		void broadcastText(std::string_view text);
		// Number of currently connected clients.
		size_t clientCount() const;

	private:
		struct OutboxItem {
			std::string data;
			bool rawFrame = false; // data is a complete, already-encoded frame
		};

		struct Client {
			explicit Client(asio::io_context &io)
				: socket(io) {}
			asio::ip::tcp::socket socket;
			std::thread senderThread;
			std::deque<OutboxItem> outbox;
			std::mutex outboxMtx;
			std::condition_variable outboxCv;
			std::atomic<bool> open{false};
			std::atomic<bool> closeAfterSend{false};
		};

		std::unique_ptr<asio::io_context> io;
		std::unique_ptr<asio::ip::tcp::acceptor> acceptor;
		std::thread acceptThread;
		std::atomic<bool> running{false};
		mutable std::mutex clientsMtx;
		std::vector<std::shared_ptr<Client>> clients;
		std::shared_ptr<const std::string> latestSnapshot;
		mutable std::mutex snapshotMtx;

		void acceptLoop();
		void handleClient(const std::shared_ptr<Client> &client);
		void readLoop(const std::shared_ptr<Client> &client);
		void closeClient(const std::shared_ptr<Client> &client);
		void senderLoop(const std::shared_ptr<Client> &client);
		void queueSend(const std::shared_ptr<Client> &client, OutboxItem &&item);

		static std::string extractHeader(std::string_view headers, std::string_view name);
		static std::string computeAcceptKey(std::string_view key);
		static std::string base64Encode(const unsigned char *data, size_t len);
		static std::string encodeTextFrame(std::string_view payload);
	};

	inline bool Server::start(uint16_t port) {
		stop();
		{
			std::lock_guard lk(snapshotMtx);
			latestSnapshot.reset();
		}

		io = std::make_unique<asio::io_context>();
		acceptor = std::make_unique<asio::ip::tcp::acceptor>(*io);

		asio::error_code ec;
		acceptor->open(asio::ip::tcp::v4(), ec);
		if (ec) {
			std::println("ws: failed to open acceptor: {}", ec.message());
			acceptor.reset();
			return false;
		}
		acceptor->set_option(asio::ip::tcp::acceptor::reuse_address(true), ec);
		acceptor->bind(asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), port), ec);
		if (ec) {
			std::println("ws: failed to bind 127.0.0.1:{}: {}", port, ec.message());
			acceptor.reset();
			return false;
		}
		acceptor->listen(asio::socket_base::max_listen_connections, ec);
		if (ec) {
			std::println("ws: failed to listen: {}", ec.message());
			acceptor.reset();
			return false;
		}

		running = true;
		acceptThread = std::thread([this]() {
			acceptLoop();
		});
		std::println("ws: live export listening on 127.0.0.1:{}", port);
		return true;
	}

	inline void Server::stop() {
		running = false;
		{
			std::lock_guard lk(clientsMtx);
			for (const auto &client: clients) {
				asio::error_code ignored;
				client->socket.close(ignored);
				client->open = false;
				client->outboxCv.notify_all();
			}
		}
		if (io) io->stop();
		if (acceptThread.joinable()) acceptThread.join();
		{
			std::lock_guard lk(clientsMtx);
			for (const auto &client: clients) {
				if (client->senderThread.joinable()) client->senderThread.join();
			}
			clients.clear();
		}
		if (acceptor) {
			asio::error_code ignored;
			acceptor->close(ignored);
		}
		acceptor.reset();
		io.reset();
	}

	inline void Server::broadcastText(std::string_view text) {
		if (!running) return;
		{
			std::lock_guard lk(snapshotMtx);
			latestSnapshot = std::make_shared<std::string>(text);
		}
		std::vector<std::shared_ptr<Client>> snapshot;
		{
			std::lock_guard lk(clientsMtx);
			snapshot = clients;
		}
		for (const auto &client: snapshot) {
			queueSend(client, OutboxItem{.data = std::string{text}});
		}
	}

	inline size_t Server::clientCount() const {
		std::lock_guard lk(clientsMtx);
		return clients.size();
	}

	inline void Server::queueSend(const std::shared_ptr<Client> &client, OutboxItem &&item) {
		std::lock_guard lk(client->outboxMtx);
		client->outbox.emplace_back(std::move(item));
		client->outboxCv.notify_one();
	}

	inline void Server::acceptLoop() {
		std::function<void()> acceptNext = [this, &acceptNext]() {
			if (!running) return;
			auto client = std::make_shared<Client>(*io);
			acceptor->async_accept(client->socket, [this, client, acceptNext](const asio::error_code &ec) {
				if (ec || !running) {
					asio::error_code ignored;
					client->socket.close(ignored);
					return;
				}
				handleClient(client);
				acceptNext();
			});
		};
		acceptNext();
		io->run();
	}

	inline void Server::handleClient(const std::shared_ptr<Client> &client) {
		auto request = std::make_shared<asio::streambuf>();
		asio::async_read_until(client->socket, *request, "\r\n\r\n", [this, client, request](const asio::error_code &ec, size_t) {
			if (ec) return closeClient(client);
			std::string headers(
				std::istreambuf_iterator<char>(request.get()),
				std::istreambuf_iterator<char>()
			);
			std::string key = extractHeader(headers, "sec-websocket-key");
			if (key.empty()) return closeClient(client);

			std::string response =
				"HTTP/1.1 101 Switching Protocols\r\n"
				"Upgrade: websocket\r\n"
				"Connection: Upgrade\r\n"
				"Sec-WebSocket-Accept: " + computeAcceptKey(key) + "\r\n\r\n";
			asio::async_write(client->socket, asio::buffer(response), [this, client](const asio::error_code &ec, size_t) {
				if (ec) return closeClient(client);

				{
					std::lock_guard lk(clientsMtx);
					clients.emplace_back(client);
				}
				client->open = true;

				// Initial snapshot: prefer the latest broadcast, otherwise request one.
				std::shared_ptr<const std::string> snap;
				{
					std::lock_guard lk(snapshotMtx);
					snap = latestSnapshot;
				}
				std::string initial = snap ? *snap : (onSnapshotRequested ? onSnapshotRequested() : std::string{});
				if (!initial.empty()) {
					queueSend(client, OutboxItem{.data = std::move(initial)});
				}

				client->senderThread = std::thread([this, client]() {
					senderLoop(client);
				});
				readLoop(client);
				std::println("ws: client connected ({} total)", clientCount());
			});
		});
	}

	inline void Server::readLoop(const std::shared_ptr<Client> &client) {
		struct Frame {
			std::array<uint8_t, 2> head{};
			std::array<uint8_t, 8> ext{};
			std::array<uint8_t, 4> mask{};
			uint64_t payloadLen = 0;
			std::vector<uint8_t> payload;
			uint8_t opcode = 0;
			bool masked = false;
		};
		auto frame = std::make_shared<Frame>();

		asio::async_read(client->socket, asio::buffer(frame->head), [this, client, frame](const asio::error_code &ec, size_t) {
			if (ec) return closeClient(client);
			frame->opcode = frame->head[0] & 0x0F;
			frame->masked = frame->head[1] & 0x80;
			uint8_t lenCode = frame->head[1] & 0x7F;

			std::function<void()> readMask = [this, client, frame, &readMask]() {
				asio::async_read(client->socket, asio::buffer(frame->mask), [this, client, frame](const asio::error_code &ec, size_t) {
					if (ec) return closeClient(client);
					if (frame->payloadLen > 64ull * 1024 * 1024) return closeClient(client);
					frame->payload.resize(static_cast<size_t>(frame->payloadLen));
					asio::async_read(client->socket, asio::buffer(frame->payload), [this, client, frame](const asio::error_code &ec, size_t) {
						if (ec) return closeClient(client);
						if (frame->masked) {
							for (size_t i = 0; i < frame->payload.size(); ++i) {
								frame->payload[i] ^= frame->mask[i % 4];
							}
						}
						switch (frame->opcode) {
							case 0x8: { // close
								client->closeAfterSend = true;
								queueSend(client, OutboxItem{}); // sender replies with a close frame
								return;
							}
							case 0x9: { // ping -> pong with the same payload
								std::string pong;
								pong.reserve(frame->payload.size() + 8);
								pong.push_back(static_cast<char>(0x8A));
								size_t len = frame->payload.size();
								if (len < 126) {
									pong.push_back(static_cast<char>(len));
								} else if (len <= 0xFFFF) {
									pong.push_back(126);
									pong.push_back(static_cast<char>((len >> 8) & 0xFF));
									pong.push_back(static_cast<char>(len & 0xFF));
								} else {
									pong.push_back(127);
									for (int i = 7; i >= 0; --i) pong.push_back(static_cast<char>((len >> (i * 8)) & 0xFF));
								}
								pong.append(reinterpret_cast<const char *>(frame->payload.data()), frame->payload.size());
								queueSend(client, OutboxItem{.data = std::move(pong), .rawFrame = true});
								break;
							}
							default:
								// text/binary/continuation from the client: nothing to act on
								break;
						}
						readLoop(client);
					});
				});
			};

			if (lenCode == 126) {
				asio::async_read(client->socket, asio::buffer(frame->ext, 2), [this, client, frame, readMask](const asio::error_code &ec, size_t) {
					if (ec) return closeClient(client);
					frame->payloadLen = (static_cast<uint64_t>(frame->ext[0]) << 8) | frame->ext[1];
					readMask();
				});
			} else if (lenCode == 127) {
				asio::async_read(client->socket, asio::buffer(frame->ext), [this, client, frame, readMask](const asio::error_code &ec, size_t) {
					if (ec) return closeClient(client);
					if (frame->ext[0] & 0x80) return closeClient(client); // MSB must be 0
					frame->payloadLen = 0;
					for (uint8_t byte: frame->ext) frame->payloadLen = (frame->payloadLen << 8) | byte;
					readMask();
				});
			} else {
				frame->payloadLen = lenCode;
				readMask();
			}
		});
	}

	inline void Server::closeClient(const std::shared_ptr<Client> &client) {
		asio::error_code ignored;
		client->socket.close(ignored);
		client->open = false;
		client->closeAfterSend = true;
		client->outboxCv.notify_all();
		{
			std::lock_guard lk(clientsMtx);
			std::erase_if(clients, [&](const auto &c) { return c == client; });
		}
		if (client->senderThread.joinable() && client->senderThread.get_id() != std::this_thread::get_id()) {
			client->senderThread.join();
		}
		std::println("ws: client disconnected ({} total)", clientCount());
	}

	inline void Server::senderLoop(const std::shared_ptr<Client> &client) {
		while (true) {
			OutboxItem item;
			{
				std::unique_lock lk(client->outboxMtx);
				client->outboxCv.wait(lk, [&]() {
					return !client->open || client->closeAfterSend.load() || !client->outbox.empty();
				});
				if (client->closeAfterSend.load()) {
					// Reply to the peer's close request, then shut down.
					try {
						asio::write(client->socket, asio::buffer(std::array<uint8_t, 2>{0x88, 0x00}));
					} catch (...) {}
					break;
				}
				if (!client->open && client->outbox.empty()) return;
				item = std::move(client->outbox.front());
				client->outbox.pop_front();
			}
			try {
				const std::string &frame = item.rawFrame ? item.data : encodeTextFrame(item.data);
				asio::write(client->socket, asio::buffer(frame));
			} catch (...) {
				break;
			}
		}
		asio::error_code ignored;
		client->socket.close(ignored);
		// No read is pending once a close frame was received/queued, so have the
		// io thread clean up the client after this sender thread has returned.
		if (io) io->post([this, client]() {
			closeClient(client);
		});
	}

	inline std::string Server::extractHeader(std::string_view headers, std::string_view name) {
		size_t pos = 0;
		while (pos <= headers.size()) {
			size_t eol = headers.find("\r\n", pos);
			if (eol == std::string_view::npos) eol = headers.size();
			std::string_view line = headers.substr(pos, eol - pos);
			size_t colon = line.find(':');
			if (colon != std::string_view::npos) {
				std::string_view lineName = line.substr(0, colon);
				if (lineName.size() == name.size()
					&& std::equal(lineName.begin(), lineName.end(), name.begin(), [](char a, char b) {
						   return static_cast<char>(std::tolower(static_cast<unsigned char>(a)))
							   == static_cast<char>(std::tolower(static_cast<unsigned char>(b)));
					   })) {
					std::string_view value = line.substr(colon + 1);
					while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
						value.remove_prefix(1);
					}
					return std::string{value};
				}
			}
			if (eol == headers.size()) break;
			pos = eol + 2;
		}
		return {};
	}

	inline std::string Server::base64Encode(const unsigned char *data, size_t len) {
		std::string out((len + 2) / 3 * 4, '\0');
		int written = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()), data, static_cast<int>(len));
		out.resize(static_cast<size_t>(written));
		return out;
	}

	inline std::string Server::computeAcceptKey(std::string_view key) {
		std::string input{key};
		input += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
		unsigned char digest[SHA_DIGEST_LENGTH];
		SHA1(reinterpret_cast<const unsigned char *>(input.data()), input.size(), digest);
		return base64Encode(digest, SHA_DIGEST_LENGTH);
	}

	inline std::string Server::encodeTextFrame(std::string_view payload) {
		std::string frame;
		frame.reserve(payload.size() + 10);
		frame.push_back(static_cast<char>(0x81));
		if (payload.size() < 126) {
			frame.push_back(static_cast<char>(payload.size()));
		} else if (payload.size() <= 0xFFFF) {
			frame.push_back(126);
			uint16_t len = static_cast<uint16_t>(payload.size());
			frame.push_back(static_cast<char>((len >> 8) & 0xFF));
			frame.push_back(static_cast<char>(len & 0xFF));
		} else {
			frame.push_back(127);
			uint64_t len = payload.size();
			for (int i = 7; i >= 0; --i) frame.push_back(static_cast<char>((len >> (i * 8)) & 0xFF));
		}
		frame.append(payload);
		return frame;
	}
}// namespace websocket