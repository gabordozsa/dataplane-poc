#include "spsc_ring.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Return true iff x is a non-zero power of two. */
static bool is_power_of_two(uint64_t x) {
    return x >= 2 && (x & (x - 1)) == 0;
}

spsc_ring_t *spsc_ring_create(uint64_t capacity) {
    if (!is_power_of_two(capacity)) {
        log_error("spsc_ring_create: capacity %llu is not a power of two",
                  (unsigned long long)capacity);
        return NULL;
    }

    spsc_ring_t *ring = calloc(1, sizeof(spsc_ring_t));
    if (!ring) {
        log_error("spsc_ring_create: failed to allocate ring struct: %s",
                  strerror(errno));
        return NULL;
    }

    ring->slots = calloc(capacity, sizeof(void *));
    if (!ring->slots) {
        log_error("spsc_ring_create: failed to allocate slots (%llu entries): %s",
                  (unsigned long long)capacity, strerror(errno));
        free(ring);
        return NULL;
    }

    ring->mask = capacity - 1;
    atomic_init(&ring->head, 0);
    atomic_init(&ring->tail, 0);

    log_debug("spsc_ring_create: created ring %p, capacity %llu",
              (void *)ring, (unsigned long long)capacity);
    return ring;
}

void spsc_ring_destroy(spsc_ring_t *ring) {
    if (!ring) {
        return;
    }
    log_debug("spsc_ring_destroy: destroying ring %p", (void *)ring);
    free(ring->slots);
    free(ring);
}

bool spsc_ring_push(spsc_ring_t *ring, void *item) {
    /*
     * The producer reads tail with acquire to observe the consumer's
     * most-recent pop.  It writes head with release so the consumer
     * sees the new slot content when it next loads head.
     */
    uint64_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint64_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);

    if (head - tail > ring->mask) {
        /* Ring is full. */
        return false;
    }

    ring->slots[head & ring->mask] = item;

    atomic_store_explicit(&ring->head, head + 1, memory_order_release);
    return true;
}

bool spsc_ring_pop(spsc_ring_t *ring, void **item_out) {
    /*
     * The consumer reads head with acquire to observe the producer's
     * most-recent push.  It writes tail with release so the producer
     * sees the freed slot when it next loads tail.
     */
    uint64_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    uint64_t head = atomic_load_explicit(&ring->head, memory_order_acquire);

    if (tail == head) {
        /* Ring is empty. */
        return false;
    }

    *item_out = ring->slots[tail & ring->mask];

    atomic_store_explicit(&ring->tail, tail + 1, memory_order_release);
    return true;
}

uint64_t spsc_ring_size(const spsc_ring_t *ring) {
    uint64_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
    uint64_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
    return head - tail;
}

bool spsc_ring_is_empty(const spsc_ring_t *ring) {
    return spsc_ring_size(ring) == 0;
}

bool spsc_ring_is_full(const spsc_ring_t *ring) {
    return spsc_ring_size(ring) > ring->mask;
}

// Made with Bob
