cmake_minimum_required(VERSION 3.10)
project(dtls_vpn_tunnel C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -DNDEBUG")

# Find required packages
find_package(OpenSSL 1.1.1 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBURING REQUIRED liburing>=2.0)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    ${LIBURING_INCLUDE_DIRS}
)

# Source files
set(COMMON_SOURCES
    src/utils.c
    src/tun_device.c
    src/udp_socket.c
    src/iouring.c
    src/dtls_context.c
    src/connection.c
    src/packet_handler.c
)

# Create static library for common code
add_library(dtls_vpn_common STATIC ${COMMON_SOURCES})
target_link_libraries(dtls_vpn_common
    ${OPENSSL_LIBRARIES}
    ${LIBURING_LIBRARIES}
)

# VPN Server executable
add_executable(vpn_server
    src/server.c
)
target_link_libraries(vpn_server
    dtls_vpn_common
    ${OPENSSL_LIBRARIES}
    ${LIBURING_LIBRARIES}
)

# VPN Client executable
add_executable(vpn_client
    src/client.c
)
target_link_libraries(vpn_client
    dtls_vpn_common
    ${OPENSSL_LIBRARIES}
    ${LIBURING_LIBRARIES}
)

# Example programs
add_executable(example_server
    examples/vpn_server.c
)
target_link_libraries(example_server
    dtls_vpn_common
    ${OPENSSL_LIBRARIES}
    ${LIBURING_LIBRARIES}
)

add_executable(example_client
    examples/vpn_client.c
)
target_link_libraries(example_client
    dtls_vpn_common
    ${OPENSSL_LIBRARIES}
    ${LIBURING_LIBRARIES}
)

# Installation
install(TARGETS vpn_server vpn_client
    RUNTIME DESTINATION bin
)

install(TARGETS dtls_vpn_common
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/
    DESTINATION include/dtls_vpn
    FILES_MATCHING PATTERN "*.h"
)

# Print configuration
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
message(STATUS "liburing libraries: ${LIBURING_LIBRARIES}")