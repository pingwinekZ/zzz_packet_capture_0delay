#pragma once

#include "../pcap/pcap.hpp"
#include "../websocket/websocketServer.hpp"
#include "core/core.hpp"
#include "data/exportSettings.hpp"

namespace ui {
	using namespace squi;

	struct Home : StatefulWidget {
		// Args
		Key key;
		Args widget{};

		struct State : WidgetState<Home> {
			bool isLoading = true;
			bool isCapturing = false;
			bool isLiveExporting = false;
			bool manifestUpdateAvailable = false;
			data::ExportSettings exportSettings;
			Pcap pcap;
			VoidObserver onEventUpdate{};
			VoidObserver wsEventObserver{};
			std::unique_ptr<websocket::Server> wsServer;

			void initState() override;

			void updateData();
			void initializeData();

			std::string makeLiveZodJson();

			void dispose() override {
				pcap.stop();
				wsServer.reset();
			}

			std::optional<std::string> getSelectedRegion();

			Child build(const Element &element) override;
		};
	};
}// namespace ui