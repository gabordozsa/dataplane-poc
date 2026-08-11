#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

static volatile log_level_t current_log_level = LOG_INFO;

bool at_log_level(log_level_t l) {
    if (current_log_level <= l) {
        return true;
    }
    return false;
}

void log_set_level(log_level_t level) {
    current_log_level = level;
}

void log_message(log_level_t level, const char *fmt, ...) {
    if (level < current_log_level) {
        return;
    }
    
    const char *level_str[] = {"DEBUG", "INFO", "WARN", "ERROR"};
    struct timeval tv;
    gettimeofday(&tv, NULL);
    
    struct tm *tm_info = localtime(&tv.tv_sec);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(stderr, "[%s.%03ld] [%s] ", time_buf, tv.tv_usec / 1000, level_str[level]);
    
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    
    fprintf(stderr, "\n");
    fflush(stderr);
}

void log_debug(const char *fmt, ...) {
    if (LOG_DEBUG < current_log_level) return;
    
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[DEBUG] ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

void log_info(const char *fmt, ...) {
    if (LOG_INFO < current_log_level) return;
    
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[INFO] ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

void log_warn(const char *fmt, ...) {
    if (LOG_WARN < current_log_level) return;
    
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[WARN] ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

void log_error(const char *fmt, ...) {
    if (LOG_ERROR < current_log_level) return;
    
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[ERROR] ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

uint64_t get_timestamp_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

const char* addr_to_string(const struct sockaddr_storage *addrs, log_level_t log_level) {
    static char buf[128];  // Static buffer for address string

    // skip if not at the desired log level
    if (!at_log_level(log_level))
        return "";

    const struct sockaddr *addr = (const struct sockaddr *)addrs;
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        snprintf(buf, sizeof(buf), "%s:%d", ip, ntohs(sin->sin_port));
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
        snprintf(buf, sizeof(buf), "[%s]:%d", ip, ntohs(sin6->sin6_port));
    } else {
        snprintf(buf, sizeof(buf), "unknown");
    }
    
    return buf;
}


uint32_t addr_hash(const struct sockaddr *addr, size_t bucket_count) {
    uint32_t hash = 0;
    
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        hash = sin->sin_addr.s_addr ^ sin->sin_port;
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        // Simple hash for IPv6
        for (int i = 0; i < 16; i += 4) {
            hash ^= *(uint32_t *)&sin6->sin6_addr.s6_addr[i];
        }
        hash ^= sin6->sin6_port;
    }
    
    return hash % bucket_count;
}

int addr_compare(const struct sockaddr *a, const struct sockaddr *b) {
    if (a->sa_family != b->sa_family) {
        return a->sa_family - b->sa_family;
    }
    
    if (a->sa_family == AF_INET) {
        struct sockaddr_in *sin_a = (struct sockaddr_in *)a;
        struct sockaddr_in *sin_b = (struct sockaddr_in *)b;
        
        if (sin_a->sin_addr.s_addr != sin_b->sin_addr.s_addr) {
            return sin_a->sin_addr.s_addr - sin_b->sin_addr.s_addr;
        }
        return sin_a->sin_port - sin_b->sin_port;
    } else if (a->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6_a = (struct sockaddr_in6 *)a;
        struct sockaddr_in6 *sin6_b = (struct sockaddr_in6 *)b;
        
        int cmp = memcmp(&sin6_a->sin6_addr, &sin6_b->sin6_addr, sizeof(struct in6_addr));
        if (cmp != 0) {
            return cmp;
        }
        return sin6_a->sin6_port - sin6_b->sin6_port;
    }
    
    return 0;
}

void addr_copy(struct sockaddr_storage *dst, const struct sockaddr *src, socklen_t len) {
    memset(dst, 0, sizeof(*dst));
    memcpy(dst, src, len);
}

bool validate_ip_packet(const uint8_t *packet, size_t len) {
    if (len < 20) {
        return false;  // Minimum IPv4 header size
    }
    
    uint8_t version = (packet[0] >> 4);
    
    if (version == 4) {
        struct iphdr *iph = (struct iphdr *)packet;
        uint16_t total_len = ntohs(iph->tot_len);
        
        if (total_len > len) {
            return false;  // Truncated packet
        }
        
        if (total_len < 20) {
            return false;  // Too short
        }
        
        // Extract IHL (Internet Header Length) from iph
        // ihl is in 32-bit words, so multiply by 4 to get bytes
        uint8_t ihl = iph->ihl;
        if (ihl < 5) {
            return false;  // Invalid header length (minimum 20 bytes = 5 words)
        }
        
        return true;
    } else if (version == 6) {
        // Basic IPv6 validation
        if (len < 40) {
            return false;  // Minimum IPv6 header size
        }
        return true;
    }
    
    return false;  // Unknown version
}

void print_ip_packet_info(const uint8_t *packet, size_t len, const char *msg) {
    if (len < 20) {
        log_debug("Packet too short: %zu bytes", len);
        return;
    }

    uint8_t version = (packet[0] >> 4);

    if (version == 4) {
        struct iphdr *iph = (struct iphdr *)packet;

        char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->saddr, src, sizeof(src));
        inet_ntop(AF_INET, &iph->daddr, dst, sizeof(dst));

        log_debug("IPv4 packet %s: %s -> %s, proto=%d, len=%d",
                  msg, src, dst, iph->protocol, ntohs(iph->tot_len));
    } else if (version == 6) {
        // IPv6 header is different structure
        struct {
            uint32_t version_class_label;
            uint16_t payload_len;
            uint8_t next_header;
            uint8_t hop_limit;
            struct in6_addr saddr;
            struct in6_addr daddr;
        } *ip6h = (void *)packet;

        char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6h->saddr, src, sizeof(src));
        inet_ntop(AF_INET6, &ip6h->daddr, dst, sizeof(dst));

        log_debug("IPv6 packet %s: %s -> %s, next=%d, len=%d",
                  msg, src, dst, ip6h->next_header, ntohs(ip6h->payload_len));
    } else {
        log_debug("Unknown IP version: %d", version);
    }
}

uint32_t get_ipv4_destination(const uint8_t *packet, size_t len) {
    if (len < 20) {
        return 0;
    }
    
    uint8_t version = (packet[0] >> 4);
    if (version != 4) {
        return 0;  // Not IPv4
    }
    
    struct iphdr *iph = (struct iphdr *)packet;
    return iph->daddr;  // Already in network byte order
}

uint32_t get_ipv4_source(const uint8_t *packet, size_t len) {
    if (len < 20) {
        return 0;
    }
    
    uint8_t version = (packet[0] >> 4);
    if (version != 4) {
        return 0;  // Not IPv4
    }
    
    struct iphdr *iph = (struct iphdr *)packet;
    return iph->saddr;  // Already in network byte order
}

// Made with Bob
