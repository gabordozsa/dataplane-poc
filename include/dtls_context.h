#ifndef DTLS_CONTEXT_H
#define DTLS_CONTEXT_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <stdbool.h>

/**
 * DTLS context for server or client
 */
typedef struct {
    SSL_CTX *ctx;
    bool is_server;
    char cert_file[256];
    char key_file[256];
} dtls_ctx_t;

/**
 * Initialize DTLS server context
 * @param cert_file Path to certificate file
 * @param key_file Path to private key file
 * @return Pointer to dtls_ctx_t on success, NULL on failure
 */
dtls_ctx_t* dtls_server_context_init(const char *cert_file, const char *key_file);

/**
 * Initialize DTLS client context
 * @param ca_file Path to CA certificate file (NULL to skip verification)
 * @return Pointer to dtls_ctx_t on success, NULL on failure
 */
dtls_ctx_t* dtls_client_context_init(const char *ca_file);

/**
 * Create SSL object for a new connection
 * @param dtls_ctx DTLS context
 * @return SSL object on success, NULL on failure
 */
SSL* dtls_create_ssl(dtls_ctx_t *dtls_ctx);

/**
 * Setup BIO pair for SSL object
 * @param ssl SSL object
 * @param rbio_ptr Pointer to store read BIO
 * @param wbio_ptr Pointer to store write BIO
 * @return 0 on success, -1 on failure
 */
int dtls_setup_bio_pair(SSL *ssl, BIO **rbio_ptr, BIO **wbio_ptr);

/**
 * Cleanup DTLS context
 * @param dtls_ctx DTLS context
 */
void dtls_context_cleanup(dtls_ctx_t *dtls_ctx);

/**
 * Cleanup SSL object
 * @param ssl SSL object
 */
void dtls_ssl_cleanup(SSL *ssl);

/**
 * Get SSL error string
 * @param ssl SSL object
 * @param ret Return value from SSL function
 * @return Error string
 */
const char* dtls_get_error_string(SSL *ssl, int ret);

/**
 * Initialize OpenSSL library (call once at startup)
 */
void dtls_library_init(void);

/**
 * Cleanup OpenSSL library (call once at shutdown)
 */
void dtls_library_cleanup(void);

#endif // DTLS_CONTEXT_H

// Made with Bob
