#include "dtls_context.h"
#include "utils.h"
#include "connection.h"
#include "packet_handler.h"
#include "iouring.h"
#include <string.h>
#include <stdlib.h>
#include <assert.h>

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
    
    // NOTE: Do NOT call SSL_set_connect_state() or SSL_set_accept_state() here
    // It should be called AFTER BIOs are set up
    
    log_debug("Created SSL object (state will be set after BIO setup)");
    
    return ssl;
}

int dtls_setup_bio_pair(SSL *ssl, BIO **rbio_ptr, BIO **wbio_ptr) {
    if (!ssl || !rbio_ptr || !wbio_ptr) {
        log_error("Invalid parameters for BIO pair setup");
        return -1;
    }
    
    // Create separate memory BIOs (not a pair!)
    // rbio: SSL reads encrypted data from network from here
    // wbio: SSL writes encrypted data to network to here
    BIO *rbio = BIO_new(BIO_s_mem());
    BIO *wbio = BIO_new(BIO_s_mem());
    
    if (!rbio || !wbio) {
        log_error("Failed to create memory BIOs");
        if (rbio) BIO_free(rbio);
        if (wbio) BIO_free(wbio);
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    // Make BIOs non-blocking
    BIO_set_mem_eof_return(rbio, -1);
    BIO_set_mem_eof_return(wbio, -1);
    
    // Associate BIOs with SSL (SSL takes ownership)
    SSL_set_bio(ssl, rbio, wbio);
    
    // NOW set the SSL state after BIOs are attached
    // Determine if server or client based on SSL state
    if (SSL_is_server(ssl)) {
        SSL_set_accept_state(ssl);
        log_debug("Set SSL to accept state (server)");
    } else {
        SSL_set_connect_state(ssl);
        log_debug("Set SSL to connect state (client)");
    }
    
    // Return the same BIOs for external use
    // We write network data to rbio, read SSL output from wbio
    *rbio_ptr = rbio;
    *wbio_ptr = wbio;
    
    log_debug("Setup memory BIOs for SSL");
    
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
