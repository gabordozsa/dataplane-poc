#include "dtls_context.h"
#include "utils.h"
#include <string.h>
#include <stdlib.h>

// Cookie generation callbacks for DoS protection
static int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    (void)ssl;
    // Simple cookie generation - in production, use HMAC with secret
    *cookie_len = 16;
    memset(cookie, 0xAB, 16);
    return 1;
}

static int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
    (void)ssl;
    (void)cookie;
    // Simple verification - in production, verify HMAC
    return (cookie_len == 16) ? 1 : 0;
}

void dtls_library_init(void) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    log_info("Initialized OpenSSL library");
}

void dtls_library_cleanup(void) {
    EVP_cleanup();
    ERR_free_strings();
    log_info("Cleaned up OpenSSL library");
}

dtls_ctx_t* dtls_server_context_init(const char *cert_file, const char *key_file) {
    if (!cert_file || !key_file) {
        log_error("Certificate and key files required for server");
        return NULL;
    }
    
    dtls_ctx_t *dtls_ctx = calloc(1, sizeof(dtls_ctx_t));
    if (!dtls_ctx) {
        log_error("Failed to allocate DTLS context");
        return NULL;
    }
    
    dtls_ctx->is_server = true;
    strncpy(dtls_ctx->cert_file, cert_file, sizeof(dtls_ctx->cert_file) - 1);
    strncpy(dtls_ctx->key_file, key_file, sizeof(dtls_ctx->key_file) - 1);
    
    // Create DTLS server context
    dtls_ctx->ctx = SSL_CTX_new(DTLS_server_method());
    if (!dtls_ctx->ctx) {
        log_error("Failed to create SSL context");
        free(dtls_ctx);
        return NULL;
    }
    
    // Load certificate
    if (SSL_CTX_use_certificate_file(dtls_ctx->ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
        log_error("Failed to load certificate from %s", cert_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(dtls_ctx->ctx);
        free(dtls_ctx);
        return NULL;
    }
    
    // Load private key
    if (SSL_CTX_use_PrivateKey_file(dtls_ctx->ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        log_error("Failed to load private key from %s", key_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(dtls_ctx->ctx);
        free(dtls_ctx);
        return NULL;
    }
    
    // Verify private key
    if (SSL_CTX_check_private_key(dtls_ctx->ctx) != 1) {
        log_error("Private key does not match certificate");
        SSL_CTX_free(dtls_ctx->ctx);
        free(dtls_ctx);
        return NULL;
    }
    
    // Set cipher suites (strong ciphers only)
    if (SSL_CTX_set_cipher_list(dtls_ctx->ctx, "HIGH:!aNULL:!MD5:!RC4") != 1) {
        log_error("Failed to set cipher list");
        SSL_CTX_free(dtls_ctx->ctx);
        free(dtls_ctx);
        return NULL;
    }
    
    // Set cookie callbacks for DoS protection
    SSL_CTX_set_cookie_generate_cb(dtls_ctx->ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(dtls_ctx->ctx, verify_cookie);
    
    // Set read ahead for DTLS
    SSL_CTX_set_read_ahead(dtls_ctx->ctx, 1);
    
    log_info("Initialized DTLS server context");
    
    return dtls_ctx;
}

dtls_ctx_t* dtls_client_context_init(const char *ca_file) {
    dtls_ctx_t *dtls_ctx = calloc(1, sizeof(dtls_ctx_t));
    if (!dtls_ctx) {
        log_error("Failed to allocate DTLS context");
        return NULL;
    }
    
    dtls_ctx->is_server = false;
    
    // Create DTLS client context
    dtls_ctx->ctx = SSL_CTX_new(DTLS_client_method());
    if (!dtls_ctx->ctx) {
        log_error("Failed to create SSL context");
        free(dtls_ctx);
        return NULL;
    }
    
    // Load CA certificate if provided
    if (ca_file) {
        if (SSL_CTX_load_verify_locations(dtls_ctx->ctx, ca_file, NULL) != 1) {
            log_error("Failed to load CA certificate from %s", ca_file);
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(dtls_ctx->ctx);
            free(dtls_ctx);
            return NULL;
        }
        SSL_CTX_set_verify(dtls_ctx->ctx, SSL_VERIFY_PEER, NULL);
        strncpy(dtls_ctx->cert_file, ca_file, sizeof(dtls_ctx->cert_file) - 1);
    } else {
        // Skip certificate verification (for testing only!)
        SSL_CTX_set_verify(dtls_ctx->ctx, SSL_VERIFY_NONE, NULL);
        log_warn("Certificate verification disabled - NOT FOR PRODUCTION");
    }
    
    // Set cipher suites
    if (SSL_CTX_set_cipher_list(dtls_ctx->ctx, "HIGH:!aNULL:!MD5:!RC4") != 1) {
        log_error("Failed to set cipher list");
        SSL_CTX_free(dtls_ctx->ctx);
        free(dtls_ctx);
        return NULL;
    }
    
    // Set read ahead for DTLS
    SSL_CTX_set_read_ahead(dtls_ctx->ctx, 1);
    
    log_info("Initialized DTLS client context");
    
    return dtls_ctx;
}

SSL* dtls_create_ssl(dtls_ctx_t *dtls_ctx) {
    if (!dtls_ctx || !dtls_ctx->ctx) {
        log_error("Invalid DTLS context");
        return NULL;
    }
    
    SSL *ssl = SSL_new(dtls_ctx->ctx);
    if (!ssl) {
        log_error("Failed to create SSL object");
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    // Set MTU to avoid fragmentation
    SSL_set_mtu(ssl, 1400);
    
    // Set mode for server or client
    if (dtls_ctx->is_server) {
        SSL_set_accept_state(ssl);
    } else {
        SSL_set_connect_state(ssl);
    }
    
    log_debug("Created SSL object");
    
    return ssl;
}

int dtls_setup_bio_pair(SSL *ssl, BIO **rbio_ptr, BIO **wbio_ptr) {
    if (!ssl || !rbio_ptr || !wbio_ptr) {
        log_error("Invalid parameters for BIO pair setup");
        return -1;
    }
    
    BIO *internal_rbio = NULL;
    BIO *internal_wbio = NULL;
    
    // Create BIO pair with 8KB buffers
    // BIO_new_bio_pair creates two connected BIOs where:
    // - Data written to bio1 can be read from bio2
    // - Data written to bio2 can be read from bio1
    if (BIO_new_bio_pair(&internal_rbio, 8192, &internal_wbio, 8192) != 1) {
        log_error("Failed to create BIO pair");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    // For DTLS with BIO pairs:
    // - SSL reads encrypted data from internal_rbio (data we write to external_wbio)
    // - SSL writes encrypted data to internal_wbio (data we read from external_rbio)
    // So we need to swap them for the external interface
    
    // Associate BIOs with SSL (SSL takes ownership)
    SSL_set_bio(ssl, internal_rbio, internal_wbio);
    
    // Return the OTHER ends of the pair for external use
    // external rbio = internal_wbio (we read SSL's output from here)
    // external wbio = internal_rbio (we write network input to here)
    *rbio_ptr = internal_wbio;  // Read SSL output from here
    *wbio_ptr = internal_rbio;  // Write network input to here
    
    log_debug("Setup BIO pair for SSL (swapped for external interface)");
    
    return 0;
}

void dtls_context_cleanup(dtls_ctx_t *dtls_ctx) {
    if (dtls_ctx) {
        if (dtls_ctx->ctx) {
            log_info("Cleaning up DTLS context");
            SSL_CTX_free(dtls_ctx->ctx);
        }
        free(dtls_ctx);
    }
}

void dtls_ssl_cleanup(SSL *ssl) {
    if (ssl) {
        log_debug("Cleaning up SSL object");
        SSL_free(ssl);  // This also frees the BIOs
    }
}

const char* dtls_get_error_string(SSL *ssl, int ret) {
    int err = SSL_get_error(ssl, ret);
    
    switch (err) {
        case SSL_ERROR_NONE:
            return "No error";
        case SSL_ERROR_ZERO_RETURN:
            return "Connection closed";
        case SSL_ERROR_WANT_READ:
            return "Want read";
        case SSL_ERROR_WANT_WRITE:
            return "Want write";
        case SSL_ERROR_WANT_CONNECT:
            return "Want connect";
        case SSL_ERROR_WANT_ACCEPT:
            return "Want accept";
        case SSL_ERROR_WANT_X509_LOOKUP:
            return "Want X509 lookup";
        case SSL_ERROR_SYSCALL:
            return "System call error";
        case SSL_ERROR_SSL:
            return "SSL error";
        default:
            return "Unknown error";
    }
}

// Made with Bob
