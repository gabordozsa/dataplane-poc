#ifndef TUN_DEVICE_H
#define TUN_DEVICE_H

#include <stdint.h>
#include <stddef.h>

#define TUN_NAME_MAX 16

typedef struct {
    int fd;
    char name[TUN_NAME_MAX];
    char ip[16];
    char netmask[16];
    int mtu;
} tun_device_t;

/**
 * Create a TUN device
 * @param name Device name (e.g., "tun0"), or NULL for auto-assignment
 * @return Pointer to tun_device_t on success, NULL on failure
 */
tun_device_t* tun_device_create(const char *name);

/**
 * Configure TUN device with IP address, netmask, and MTU
 * @param tun TUN device
 * @param ip IP address (e.g., "10.8.0.1")
 * @param netmask Netmask (e.g., "255.255.255.0")
 * @param mtu MTU size (typically 1400 for VPN)
 * @return 0 on success, -1 on failure
 */
int tun_device_configure(tun_device_t *tun, const char *ip, 
                         const char *netmask, int mtu);

/**
 * Bring TUN device up
 * @param tun TUN device
 * @return 0 on success, -1 on failure
 */
int tun_device_up(tun_device_t *tun);

/**
 * Bring TUN device down
 * @param tun TUN device
 * @return 0 on success, -1 on failure
 */
int tun_device_down(tun_device_t *tun);

/**
 * Destroy TUN device and free resources
 * @param tun TUN device
 */
void tun_device_destroy(tun_device_t *tun);

/**
 * Setup a new tun device
 */
 tun_device_t *new_tun_device(const char *ifname, const char *ip, const char *netmask, int mtu);

#endif // TUN_DEVICE_H

// Made with Bob
