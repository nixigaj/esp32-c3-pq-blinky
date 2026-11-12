#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TLS13_GROUP_X25519MLKEM768          0x11EC
#define TLS13_CIPHER_CHACHA20_POLY1305_SHA256 0x1303

typedef struct {
    int fd;
    uint8_t c_ap_key[32];
    uint8_t c_ap_iv[12];
    uint64_t c_ap_seq;
    uint8_t s_ap_key[32];
    uint8_t s_ap_iv[12];
    uint64_t s_ap_seq;
    char client_cn[64];
    /* Buffered plaintext from last decrypted application record */
    uint8_t rx_plain[1024];
    size_t rx_plain_len;
    size_t rx_plain_off;
    /* Handshake memory metrics */
    size_t hs_static_bytes;
    size_t hs_peak_heap_bytes;
} pq_mtls_conn_t;

/**
 * Perform a full TLS 1.3 mutual-TLS server handshake on `fd`, enforcing:
 *   - Post-Quantum Hybrid Key Exchange: X25519MLKEM768 (0x11EC)
 *   - AEAD Stream Cipher Suite: TLS_CHACHA20_POLY1305_SHA256 (0x1303)
 *   - Mutual authentication (verifies client X.509 certificate against CA_CERT_DER
 *     and verifies client's CertificateVerify signature + Finished MAC).
 *
 * Returns 0 on success, or negative error code on failure.
 */
int pq_mtls_server_handshake(pq_mtls_conn_t *conn, int fd);

/**
 * Encrypt and send application data over the established TLS 1.3 session
 * using TLS_CHACHA20_POLY1305_SHA256.
 * Returns number of plaintext bytes written, or negative on error.
 */
int pq_mtls_write(pq_mtls_conn_t *conn, const void *data, size_t len);

/**
 * Read and decrypt application data from the established TLS 1.3 session.
 * Returns >0 (bytes read), 0 on clean EOF / close_notify, or <0 on error.
 */
int pq_mtls_read(pq_mtls_conn_t *conn, void *buf, size_t max_len);

#ifdef __cplusplus
}
#endif
