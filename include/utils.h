#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>
#include <sys/socket.h>

// Log levels
typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARN = 2,
    LOG_ERROR = 3
} log_level_t;

#define LOG_LEVEL LOG_INFO

bool at_log_level(log_level_t l);

// Logging functions
void log_set_level(log_level_t level);
void log_message(log_level_t level, const char *fmt, ...);
void log_debug(const char *fmt, ...);
void log_info(const char *fmt, ...);
void log_warn(const char *fmt, ...);
void log_error(const char *fmt, ...);

// Time utilities
uint64_t get_timestamp_ms(void);
uint64_t get_timestamp_us(void);

// Address utilities
const char* addr_to_string(const struct sockaddr *addr);
uint32_t addr_hash(const struct sockaddr *addr, size_t bucket_count);
int addr_compare(const struct sockaddr *a, const struct sockaddr *b);
void addr_copy(struct sockaddr_storage *dst, const struct sockaddr *src, socklen_t len);

// IP packet validation and parsing
bool validate_ip_packet(const uint8_t *packet, size_t len);
void print_ip_packet_info(const uint8_t *packet, size_t len, const char* msg);
uint32_t get_ipv4_destination(const uint8_t *packet, size_t len);
uint32_t get_ipv4_source(const uint8_t *packet, size_t len);

// Helper macros
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#endif // UTILS_H

// Made with Bob
