cmake_minimum_required(VERSION 3.21)
set(VCPKG_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/glt/vcpkg")
set(CMAKE_TOOLCHAIN_FILE "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
set(VCPKG_OVERLAY_PORTS "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg-overlay-ports")
if(WIN32)
    set(X_VCPKG_APPLOCAL_DEPS_INSTALL ON)
endif()
project(zzz_packet_capture VERSION 0.1.0 LANGUAGES C CXX)

add_custom_target(Assets)
# Create the assets folder
add_custom_command(TARGET Assets PRE_BUILD
COMMAND ${CMAKE_COMMAND} -E make_directory $<TARGET_FILE_DIR:zzz_packet_capture>/assets)
# Make a copy in the executable directory
add_custom_command(TARGET Assets PRE_BUILD
COMMAND ${CMAKE_COMMAND} -E copy_directory "${PROJECT_SOURCE_DIR}/assets" $<TARGET_FILE_DIR:zzz_packet_capture>/assets)
# Make an additional copy in the binary dir in case a multi config generator is used
add_custom_command(TARGET Assets PRE_BUILD
COMMAND ${CMAKE_COMMAND} -E copy_directory "${PROJECT_SOURCE_DIR}/assets" ${PROJECT_BINARY_DIR}/assets)

file(GLOB_RECURSE all_files CONFIGURE_DEPENDS "src/*.cpp" "src/*.cc" "src/*.h" "src/*.hpp")
add_executable(zzz_packet_capture main.cpp ${all_files})
target_compile_features(zzz_packet_capture PUBLIC cxx_std_23)
target_include_directories(zzz_packet_capture PRIVATE src)
target_compile_definitions(zzz_packet_capture PRIVATE NOMINMAX)

if(WIN32)
    # Require admin privileges so that WinDivert driver can be loaded
    target_link_options(zzz_packet_capture PRIVATE
        "LINKER:/manifest:embed"
    )

    target_link_options(zzz_packet_capture PRIVATE
        "$<$<NOT:$<CONFIG:Debug>>:LINKER:/manifestuac:level='requireAdministrator' uiAccess='false'>"
        "$<$<NOT:$<CONFIG:Debug>>:LINKER:/SUBSYSTEM:WINDOWS>"
        "$<$<NOT:$<CONFIG:Debug>>:LINKER:/ENTRY:mainCRTStartup>"
    )
endif()
add_dependencies(zzz_packet_capture Assets)

# Offline validation tool: replays recorded cmd dumps through the live-sync parser.
# EXCLUDE_FROM_ALL so release builds/packages only ship zzz_packet_capture;
# build explicitly via `ninja zzz_sync_replay` when needed.
add_executable(zzz_sync_replay EXCLUDE_FROM_ALL tools/replay_sync.cpp)
target_compile_features(zzz_sync_replay PUBLIC cxx_std_23)
target_include_directories(zzz_sync_replay PRIVATE src glt/include)
target_compile_definitions(zzz_sync_replay PRIVATE NOMINMAX)
target_link_libraries(zzz_sync_replay PRIVATE glaze::glaze protobuf::libprotobuf protobuf::libprotobuf-lite)

# Self-test for the WebSocket live-export server (dev-only, see above)
add_executable(zzz_ws_test EXCLUDE_FROM_ALL tools/ws_test.cpp)
target_compile_features(zzz_ws_test PUBLIC cxx_std_23)
target_include_directories(zzz_ws_test PRIVATE src)
target_compile_definitions(zzz_ws_test PRIVATE NOMINMAX)
target_link_libraries(zzz_ws_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Standalone server harness for E2E tests with a real WebSocket client (dev-only)
add_executable(zzz_ws_serve EXCLUDE_FROM_ALL tools/ws_serve.cpp)
target_compile_features(zzz_ws_serve PUBLIC cxx_std_23)
target_include_directories(zzz_ws_serve PRIVATE src)
target_compile_definitions(zzz_ws_serve PRIVATE NOMINMAX)
target_link_libraries(zzz_ws_serve PRIVATE OpenSSL::SSL OpenSSL::Crypto)

add_subdirectory(glt)

target_link_libraries(zzz_packet_capture PRIVATE glt)

if(WIN32)
    find_package(WinDivert CONFIG REQUIRED)

    add_custom_command(TARGET zzz_packet_capture POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/bin/WinDivert64.sys"
            "$<TARGET_FILE_DIR:zzz_packet_capture>/WinDivert64.sys"
    )
endif()

find_package(PcapPlusPlus CONFIG REQUIRED)
target_link_libraries(zzz_packet_capture PRIVATE PcapPlusPlus::Pcap++ PcapPlusPlus::Common++)

find_package(glaze CONFIG REQUIRED)
target_link_libraries(zzz_packet_capture PRIVATE glaze::glaze)

find_package(OpenSSL REQUIRED)
target_link_libraries(zzz_packet_capture PRIVATE OpenSSL::SSL OpenSSL::Crypto)

find_package(protobuf CONFIG REQUIRED)
target_link_libraries(zzz_packet_capture PRIVATE protobuf::libupb protobuf::libprotoc protobuf::libprotobuf protobuf::libprotobuf-lite)

get_property(_imported_targets DIRECTORY ${CMAKE_SOURCE_DIR} PROPERTY IMPORTED_TARGETS)
foreach(_t IN LISTS _imported_targets)
	get_target_property(_libs ${_t} INTERFACE_LINK_LIBRARIES)
	if(_libs)
		list(FILTER _libs EXCLUDE REGEX "^-ignore:[0-9]+$")
		set_property(TARGET ${_t} PROPERTY INTERFACE_LINK_LIBRARIES "${_libs}")
	endif()
	get_target_property(_opts ${_t} INTERFACE_LINK_OPTIONS)
	if(_opts)
		list(FILTER _opts EXCLUDE REGEX "^-ignore:[0-9]+$")
		set_property(TARGET ${_t} PROPERTY INTERFACE_LINK_OPTIONS "${_opts}")
	endif()
endforeach()

set_target_properties(glaze::glaze PROPERTIES
    INTERFACE_COMPILE_OPTIONS "\$<\$<COMPILE_LANG_AND_ID:CXX,MSVC>:/Zc:preprocessor;/permissive-;/Zc:lambda;\$<\$<CONFIG:Release>:/GL>;\$<\$<CONFIG:MinSizeRel>:/GL>>"
    INTERFACE_LINK_OPTIONS "\$<\$<COMPILE_LANG_AND_ID:CXX,MSVC>:\$<\$<CONFIG:Release>:/LTCG;/INCREMENTAL:NO>;\$<\$<CONFIG:MinSizeRel>:/LTCG;/INCREMENTAL:NO>>"
)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
