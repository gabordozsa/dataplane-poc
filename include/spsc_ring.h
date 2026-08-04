#ifndef SPSC_RING_H
#define SPSC_RING_H

/*
 * Lock-free Single-Producer Single-Consumer (SPSC) ring buffer.
 *
 * Constraints:
 *  - Exactly one thread may call spsc_ring_push() at a time (producer).
 *  - Exactly one thread may call spsc_ring_pop()  at a time (consumer).
 *  - capacity must be a power of two (enforced at init time).
 *
 * Memory ordering:
 *  - head (write index) is owned by the producer.
 *  - tail (read  index) is owned by the consumer.
 *  - Acquire/release semantics on the shared index loads/stores are
 *    sufficient to guarantee visibility without a mutex.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

/* Each slot stores a plain void pointer. */
typedef struct {
    _Atomic uint64_t head;          /* next write position (producer-owned) */
    char             _pad0[64 - sizeof(_Atomic uint64_t)];
    _Atomic uint64_t tail;          /* next read  position (consumer-owned) */
    char             _pad1[64 - sizeof(_Atomic uint64_t)];
    uint64_t         mask;          /* capacity - 1 (immutable after init)  */
    void           **slots;         /* pointer array of length capacity      */
} spsc_ring_t;

/**
 * Allocate and initialise a new SPSC ring buffer.
 *
 * @param capacity  Number of slots.  Must be a power of two and >= 2.
 * @return          Pointer to the new ring on success, NULL on failure.
 */
spsc_ring_t *spsc_ring_create(uint64_t capacity);

/**
 * Destroy a ring buffer created with spsc_ring_create().
 * Does not free the items stored in slots – the caller is responsible.
 *
 * @param ring  Ring to destroy.  Passing NULL is a no-op.
 */
void spsc_ring_destroy(spsc_ring_t *ring);

/**
 * Push one item onto the ring (producer side).
 *
 * @param ring  Ring buffer.
 * @param item  Item to push.  NULL is a valid value.
 * @return      true  on success,
 *              false if the ring is full.
 */
bool spsc_ring_push(spsc_ring_t *ring, void *item);

/**
 * Pop one item from the ring (consumer side).
 *
 * @param ring      Ring buffer.
 * @param item_out  Output pointer; set to the popped item on success.
 * @return          true  on success,
 *                  false if the ring is empty.
 */
bool spsc_ring_pop(spsc_ring_t *ring, void **item_out);

/**
 * Return the number of items currently in the ring.
 * The value is approximate when called from a thread that is neither
 * the sole producer nor the sole consumer.
 *
 * @param ring  Ring buffer.
 * @return      Number of items in the ring.
 */
uint64_t spsc_ring_size(const spsc_ring_t *ring);

/**
 * Return true if the ring is empty (approximate; see spsc_ring_size).
 */
bool spsc_ring_is_empty(const spsc_ring_t *ring);

/**
 * Return true if the ring is full (approximate; see spsc_ring_size).
 */
bool spsc_ring_is_full(const spsc_ring_t *ring);

#endif /* SPSC_RING_H */

// Made with Bob
