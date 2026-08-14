// Standalone WebSocket live-export server harness for E2E testing:
//   zzz_ws_serve [port] [payload.json]
// Serves the given payload (or a minimal empty ZOD) as the initial snapshot
// and rebroadcasts it every 2s, simulating inventory change events. Runs
// until killed.

#include "websocket/websocketServer.hpp"

#include <chrono>
#include <fstream>
#include <print>
#include <string>
#include <thread>

int main(int argc, char **argv) {
	uint16_t port = 23313;
	std::string payload =
		"{\"format\":\"ZOD\",\"version\":1,\"source\":\"ZZZ Packet Capture\",\"characters\":null,\"discs\":null,\"wengines\":null}";
	if (argc > 1) port = static_cast<uint16_t>(std::stoi(argv[1]));
	if (argc > 2) {
		std::ifstream file(argv[2]);
		payload.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
	}

	websocket::Server server;
	server.onSnapshotRequested = [&]() {
		return payload;
	};
	if (!server.start(port)) return 1;

	while (true) {
		std::this_thread::sleep_for(std::chrono::seconds(2));
		server.broadcastText(payload);
	}
}