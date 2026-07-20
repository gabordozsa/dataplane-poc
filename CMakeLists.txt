cmake_minimum_required(VERSION 3.10)
project(dtls_tunnel C)

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
    src/tun_udp_run.c
)

# Create static library for common code
add_library(dtls_common STATIC ${COMMON_SOURCES})
target_link_libraries(dtls_common
    ${OPENSSL_LIBRARIES}
    ${LIBURING_LIBRARIES}
)

# Edge executable
add_executable(edge
    src/edge.c
)
target_link_libraries(edge
    dtls_common
    ${OPENSSL_LIBRARIES}
    ${LIBURING_LIBRARIES}
)

# Edge_zero executable
add_executable(edge_zero
    src/edge_zero.c
)
target_link_libraries(edge_zero
    dtls_common
    ${OPENSSL_LIBRARIES}
    ${LIBURING_LIBRARIES}
)

# DTLS Forwarder executable
add_executable(dtls_forwarder
    src/forwarder.c
)
target_link_libraries(dtls_forwarder
    dtls_common
    ${OPENSSL_LIBRARIES}
    ${LIBURING_LIBRARIES}
)

# Installation
install(TARGETS edge dtls_forwarder
    RUNTIME DESTINATION bin
)

install(TARGETS dtls_common
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/
    DESTINATION include/dtls
    FILES_MATCHING PATTERN "*.h"
)

# Print configuration
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
message(STATUS "liburing libraries: ${LIBURING_LIBRARIES}")