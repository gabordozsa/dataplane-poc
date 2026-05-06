#ifndef IOURING_H
#define IOURING_H

#include <liburing.h>
#include <stdint.h>
#include <sys/socket.h>

// Operation types for user_data
#define OP_TYPE_TUN_READ    1
#define OP_TYPE_TUN_WRITE   2
#define OP_TYPE_UDP_RECV    3
#define OP_TYPE_UDP_SEND    4

// Buffer size for packets (MTU + overhead)
#define PACKET_BUFFER_SIZE  2048

// I/O operation context
typedef struct {
    int op_type;
    void *user_data;
    uint8_t buffer[PACKET_BUFFER_SIZE];
    struct msghdr msg;
    struct iovec iov;
    struct sockaddr_storage addr;
    socklen_t addr_len;
} io_op_t;

// io-uring context
typedef struct {
    struct io_uring ring;
    unsigned queue_depth;
    int tun_fd;
    int udp_fd;
} iouring_ctx_t;

/**
 * Initialize io-uring context
 * @param queue_depth Queue depth (e.g., 256)
 * @return Pointer to iouring_ctx_t on success, NULL on failure
 */
iouring_ctx_t* iouring_init(unsigned queue_depth);

/**
 * Set file descriptors for I/O operations
 * @param ctx io-uring context
 * @param tun_fd TUN device file descriptor
 * @param udp_fd UDP socket file descriptor
 */
void iouring_set_fds(iouring_ctx_t *ctx, int tun_fd, int udp_fd);

/**
 * Submit a TUN read operation
 * @param ctx io-uring context
 * @param op I/O operation context
 * @return 0 on success, -1 on failure
 */
int iouring_submit_tun_read(iouring_ctx_t *ctx, io_op_t *op);

/**
 * Submit a TUN write operation
 * @param ctx io-uring context
 * @param op I/O operation context
 * @param data Data to write
 * @param len Length of data
 * @return 0 on success, -1 on failure
 */
int iouring_submit_tun_write(iouring_ctx_t *ctx, io_op_t *op,
                             const uint8_t *data, size_t len);

/**
 * Submit a UDP receive operation
 * @param ctx io-uring context
 * @param op I/O operation context
 * @return 0 on success, -1 on failure
 */
int iouring_submit_udp_recv(iouring_ctx_t *ctx, io_op_t *op);

/**
 * Submit a UDP send operation
 * @param ctx io-uring context
 * @param op I/O operation context
 * @param addr Destination address
 * @param data Data to send
 * @param len Length of data
 * @return 0 on success, -1 on failure
 */
int iouring_submit_udp_send(iouring_ctx_t *ctx, io_op_t *op,
                            const struct sockaddr *addr, socklen_t addr_len,
                            const uint8_t *data, size_t len);

/**
 * Wait for a completion event
 * @param ctx io-uring context
 * @param cqe_ptr Pointer to store completion queue entry
 * @return 0 on success, -1 on failure
 */
int iouring_wait_cqe(iouring_ctx_t *ctx, struct io_uring_cqe **cqe_ptr);

/**
 * Peek for a completion event (non-blocking)
 * @param ctx io-uring context
 * @param cqe_ptr Pointer to store completion queue entry
 * @return 0 if event available, -EAGAIN if not, -1 on error
 */
int iouring_peek_cqe(iouring_ctx_t *ctx, struct io_uring_cqe **cqe_ptr);

/**
 * Mark completion event as seen
 * @param ctx io-uring context
 * @param cqe Completion queue entry
 */
void iouring_cqe_seen(iouring_ctx_t *ctx, struct io_uring_cqe *cqe);

/**
 * Cleanup io-uring context
 * @param ctx io-uring context
 */
void iouring_cleanup(iouring_ctx_t *ctx);

/**
 * Allocate I/O operation context
 * @param op_type Operation type
 * @return Pointer to io_op_t on success, NULL on failure
 */
io_op_t* io_op_alloc(int op_type);

/**
 * Free I/O operation context
 * @param op I/O operation context
 */
void io_op_free(io_op_t *op);

#endif // IOURING_H

// Made with Bob
