#include "tun_device.h"
#include "utils.h"
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

tun_device_t* tun_device_create(const char *name) {
    tun_device_t *tun = calloc(1, sizeof(tun_device_t));
    if (!tun) {
        log_error("Failed to allocate memory for TUN device");
        return NULL;
    }
    
    struct ifreq ifr;
    int fd;
    
    // Open the TUN/TAP device
    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        log_error("Failed to open /dev/net/tun: %s", strerror(errno));
        free(tun);
        return NULL;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    
    // Flags:
    // IFF_TUN   - TUN device (no Ethernet headers)
    // IFF_NO_PI - Do not provide packet information
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    
    // If a device name was specified, use it
    if (name) {
        strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    }
    
    // Create the device
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        log_error("Failed to create TUN device: %s", strerror(errno));
        close(fd);
        free(tun);
        return NULL;
    }
    
    tun->fd = fd;
    strncpy(tun->name, ifr.ifr_name, sizeof(tun->name) - 1);
    
    log_info("Created TUN device: %s (fd=%d)", tun->name, tun->fd);
    
    return tun;
}

int tun_device_configure(tun_device_t *tun, const char *ip,
                         const char *netmask, int mtu) {
    if (!tun || !ip || !netmask) {
        log_error("Invalid parameters for TUN configuration");
        return -1;
    }
    
    struct ifreq ifr;
    struct sockaddr_in *addr;
    int sockfd;
    
    // Create socket for ioctl operations
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        log_error("Failed to create socket for ioctl: %s", strerror(errno));
        return -1;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, tun->name, IFNAMSIZ - 1);
    
    // Set IP address
    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &addr->sin_addr) != 1) {
        log_error("Invalid IP address: %s", ip);
        close(sockfd);
        return -1;
    }
    
    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        log_error("Failed to set IP address: %s", strerror(errno));
        close(sockfd);
        return -1;
    }
    
    // Set netmask
    addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    addr->sin_family = AF_INET;
    if (inet_pton(AF_INET, netmask, &addr->sin_addr) != 1) {
        log_error("Invalid netmask: %s", netmask);
        close(sockfd);
        return -1;
    }
    
    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
        log_error("Failed to set netmask: %s", strerror(errno));
        close(sockfd);
        return -1;
    }
    
    // Set MTU
    ifr.ifr_mtu = mtu;
    if (ioctl(sockfd, SIOCSIFMTU, &ifr) < 0) {
        log_error("Failed to set MTU: %s", strerror(errno));
        close(sockfd);
        return -1;
    }
    
    close(sockfd);
    
    // Save configuration
    strncpy(tun->ip, ip, sizeof(tun->ip) - 1);
    strncpy(tun->netmask, netmask, sizeof(tun->netmask) - 1);
    tun->mtu = mtu;
    
    log_info("Configured TUN device %s: IP=%s, netmask=%s, MTU=%d",
             tun->name, ip, netmask, mtu);
    
    return 0;
}

static int tun_device_disable_ipv6(const char *ifname) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/disable_ipv6", ifname);
    
    FILE *f = fopen(path, "w");
    if (!f) {
        log_warn("Failed to open %s: %s (IPv6 may still be enabled)", path, strerror(errno));
        return -1;
    }
    
    if (fprintf(f, "1\n") < 0) {
        log_warn("Failed to write to %s: %s", path, strerror(errno));
        fclose(f);
        return -1;
    }
    
    fclose(f);
    log_info("Disabled IPv6 on interface %s", ifname);
    return 0;
}

int tun_device_up(tun_device_t *tun) {
    if (!tun) {
        log_error("Invalid TUN device");
        return -1;
    }
    
    struct ifreq ifr;
    int sockfd;
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        log_error("Failed to create socket for ioctl: %s", strerror(errno));
        return -1;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, tun->name, IFNAMSIZ - 1);
    
    // Get current flags
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        log_error("Failed to get interface flags: %s", strerror(errno));
        close(sockfd);
        return -1;
    }
    
    // Set UP and RUNNING flags
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        log_error("Failed to bring interface up: %s", strerror(errno));
        close(sockfd);
        return -1;
    }
    
    close(sockfd);
    
    log_info("Brought TUN device %s up", tun->name);
    
    // Disable IPv6 on the interface
    tun_device_disable_ipv6(tun->name);
    
    return 0;
}

int tun_device_down(tun_device_t *tun) {
    if (!tun) {
        log_error("Invalid TUN device");
        return -1;
    }
    
    struct ifreq ifr;
    int sockfd;
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        log_error("Failed to create socket for ioctl: %s", strerror(errno));
        return -1;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, tun->name, IFNAMSIZ - 1);
    
    // Get current flags
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        log_error("Failed to get interface flags: %s", strerror(errno));
        close(sockfd);
        return -1;
    }
    
    // Clear UP flag
    ifr.ifr_flags &= ~IFF_UP;
    
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        log_error("Failed to bring interface down: %s", strerror(errno));
        close(sockfd);
        return -1;
    }
    
    close(sockfd);
    
    log_info("Brought TUN device %s down", tun->name);
    
    return 0;
}

void tun_device_destroy(tun_device_t *tun) {
    if (tun) {
        if (tun->fd >= 0) {
            log_info("Closing TUN device %s (fd=%d)", tun->name, tun->fd);
            close(tun->fd);
        }
        free(tun);
    }
}

// Made with Bob
