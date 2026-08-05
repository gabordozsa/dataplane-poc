#ifndef IOURING_H
#define IOURING_H

#include  "spsc_ring.h"

#include <liburing.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>


#define HAS_MULTI_RECV true
#define USE_MULTI_RECV true

#define HAS_MULTI_READ false
#define USE_MULTI_READ false

#if !(HAS_MULTI_RECV)
void io_uring_prep_recvmsg_multishot(struct io_uring_sqe *sqe,
                                     int fd,
                                     struct msghdr *msg,
                                     unsigned flags)  __attribute__((weak));
#endif /*MULTI_RECV*/

#if !(HAS_MULTI_READ)
void io_uring_prep_read_multishot(struct io_uring_sqe *sqe,
                                  int fd,
                                  unsigned nbytes,
                                  __u64 offset,
                                  int buf_group);
#endif /*MULTI_READ*/

// Operation types for user_data
#define OP_TYPE_TUN_READ    1
#define OP_TYPE_TUN_WRITE   2
#define OP_TYPE_UDP_RECV    3
#define OP_TYPE_UDP_SEND    4



// Pauload buffer size. Assuming TUN MTU 1400 and UDP link MTU 1500
// Normal payload: IP packet from TUN
// DTLS encryption overhead: max 45 bytes
// IP + UDP header : 40(max assumed) + 8
// Normal UDP packet size: 1400(tun) + 45(dtls) + 40(iph) + 8(udph) < 1500 bytes
// We use 1600 because multishot ops places address (and
// control info) into the provided buffers, too.
// Also, we can have larger UDP payloads during the DTLS handshake.
#define BUF_SIZE      1600

// buffer pool items (for single-shot ops)
struct buf_addr_t {
    uint8_t buf[BUF_SIZE];
    int data_len;
    struct sockaddr_storage addr;
    struct buf_addr_t *next; // next io_buf_t in the free pool
};
typedef struct buf_addr_t buf_addr_t;

// I/O operation context
struct io_op_t {
    int op_type;
    int fd;  // Fle descriptor for this operation
    bool is_multi;
    uint8_t *buffer;
    int data_len;
    int buf_idx; // if buffer is from multishot buffer ring
    buf_addr_t *buf_addr; // if buffer is from single-shot pool
    struct msghdr msg;
    struct iovec iov;
    struct sockaddr_storage *addr;
    socklen_t addr_len;
    struct io_op_t *next; // next op in the free pool
};
typedef struct io_op_t io_op_t;

// stats
typedef struct {
    int multi_recv_rearmed;
} io_stats_t;

typedef struct {
    const int sq_depth;
    const int cq_depth;
    const int br_gid;    // buffer ring group id for multi-shot ops
    const int br_n_bufs; // number of bufs in buffer ring for multi-shot ops
    const int n_io_ops;  // size of io_op  pool
    const int n_initial_recv_ops; // number of initial single-shot recvs submitted
    const int n_initial_read_ops; // number of initial single-shot reads submitted
    const int tr_depth; // transfer ring depth (to transfer data to the other thread)
    const char *name;   // name to corellate log messages
} iouring_config_t;

// io-uring context
struct iouring_ctx_t {
    iouring_config_t *config; // config params
    struct io_uring ring;
    io_op_t *io_op_pool;
    buf_addr_t *buf_addr_pool;
    uint8_t *br_bufs;
    struct io_uring_buf_ring *br;
    spsc_ring_t *transfer; // to transfer data to the other thread
    io_stats_t stats;
};
typedef struct iouring_ctx_t iouring_ctx_t;

/**
 * Initialize io-uring context
 * @param queue_depth Queue depth (e.g., 256)
 * @return Pointer to iouring_ctx_t on success, NULL on failure
 */
iouring_ctx_t* iouring_init(iouring_config_t *c);

/**
 * Create and submoit a multishot recvmg request
 */
int iouring_submit_multishot_recvmsg(iouring_ctx_t *ctx, int fd);

/**
 * Configure io_op with the result of a completed multishot recvmsg
 */
int iouring_multishot_recvmsg_out(iouring_ctx_t *ctx, io_op_t *op, unsigned cqe_flags);

/**
 * Configure io_op with the result of a completed multishot read
 */
int iouring_multishot_read_out(iouring_ctx_t *ctx, io_op_t *op, unsigned cqe_flags);

/**
 * Create and submoit a multishot read request
 */
int iouring_submit_multishot_read(iouring_ctx_t *ctx, int fd);

/**
 * Submit initial UDP recveives
 */
int iouring_initial_udp_recvs(iouring_ctx_t *ctx, int fd);

/**
 * Submit initial TUN reads
 */
int iouring_initial_tun_reads(iouring_ctx_t *ctx, int fd);

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
                             const uint8_t *data, int len);

/**
 * Submit a UDP receive operation
 * @param ctx io-uring context
 * @param udp_fd UDP socket file descriptor
 * @param op I/O operation context
 * @return 0 on success, -1 on failure
 */
int iouring_submit_udp_recv(iouring_ctx_t *ctx, io_op_t *op);

/**
 * Submit a UDP send operation
 * @param ctx io-uring context
 * @param udp_fd UDP socket file descriptor
 * @param op I/O operation context
 * @param addr Destination address
 * @param data Data to send
 * @param len Length of data
 * @return 0 on success, -1 on failure
 */
int iouring_submit_udp_send(iouring_ctx_t *ctx, io_op_t *op,
                            const struct sockaddr *addr, socklen_t addr_len,
                            const uint8_t *data, int len);

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
 * @param fd File descriptor
 * @param is_multi True if it is a multi-shot I/O operation
 * @return Pointer to io_op_t on success, NULL on failure
 */
io_op_t* io_op_alloc(iouring_ctx_t *ctx, int op_type, int fd, bool is_multi);

/**
 *  Allocate I/O operation context with the provided data-addr buffer item
 */
io_op_t* io_op_alloc_buf(iouring_ctx_t *ctx, int op_type, int fd, bool is_multi, buf_addr_t *buf_addr);

/**
 * Free I/O operation context
 * @param op I/O operation context
 */
void io_op_free(iouring_ctx_t *ctx, io_op_t **op);

/**
 * Get the name of an IO op type as a string
 */
const char *op_type_str(int op_type);

/**
 * Resubmit a completed receive op
 */
int iouring_resubmit_recv(iouring_ctx_t *uring_ctx, io_op_t *completed);

/**
 * Get a buf_addr_t struct from the pool
 */
buf_addr_t *iouring_get_buf_addr(iouring_ctx_t *ctx);

#endif // IOURING_H

// Made with Bob
