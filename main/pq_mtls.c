#include "pq_mtls.h"
#include "mlkem768.h"
#include "certs.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>

#ifdef ESP_PLATFORM
#include "esp_system.h"
#include "esp_random.h"
#include "esp_log.h"
#include "psa/crypto.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"
static const char *TAG = "pq_mtls";
#define PQ_LOGI(fmt, ...) ESP_LOGI(TAG, fmt, ##__VA_ARGS__)
#define PQ_LOGE(fmt, ...) ESP_LOGE(TAG, fmt, ##__VA_ARGS__)
static size_t s_hs_min_free_heap = 0;
static inline void pq_sample_heap(void) {
    size_t cur = esp_get_free_heap_size();
    if (s_hs_min_free_heap == 0 || cur < s_hs_min_free_heap) {
        s_hs_min_free_heap = cur;
    }
}
#else
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#define PQ_LOGI(fmt, ...) fprintf(stderr, "[pq_mtls INFO] " fmt "\n", ##__VA_ARGS__)
#define PQ_LOGE(fmt, ...) fprintf(stderr, "[pq_mtls ERROR] " fmt "\n", ##__VA_ARGS__)
static inline void pq_sample_heap(void) {}
#endif

/* =========================================================================
 * 1. SHA-256, HMAC-SHA256, and TLS 1.3 HKDF-SHA256
 * ========================================================================= */

typedef struct {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t buffer[64];
} sha256_ctx_t;

static const uint32_t sha256_k[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

static inline uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[4 * i] << 24) |
               ((uint32_t)data[4 * i + 1] << 16) |
               ((uint32_t)data[4 * i + 2] << 8) |
               ((uint32_t)data[4 * i + 3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + sha256_k[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256_init(sha256_ctx_t *ctx) {
    ctx->state[0] = 0x6a09e667UL; ctx->state[1] = 0xbb67ae85UL;
    ctx->state[2] = 0x3c6ef372UL; ctx->state[3] = 0xa54ff53aUL;
    ctx->state[4] = 0x510e527fUL; ctx->state[5] = 0x9b05688cUL;
    ctx->state[6] = 0x1f83d9abUL; ctx->state[7] = 0x5be0cd19UL;
    ctx->bitcount = 0;
}

static void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    size_t idx = (size_t)((ctx->bitcount >> 3) & 0x3F);
    ctx->bitcount += (uint64_t)len << 3;
    if (idx > 0) {
        size_t left = 64 - idx;
        if (len < left) {
            memcpy(ctx->buffer + idx, data, len);
            return;
        }
        memcpy(ctx->buffer + idx, data, left);
        sha256_transform(ctx->state, ctx->buffer);
        data += left;
        len -= left;
    }
    while (len >= 64) {
        sha256_transform(ctx->state, data);
        data += 64;
        len -= 64;
    }
    if (len > 0) {
        memcpy(ctx->buffer, data, len);
    }
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t out[32]) {
    sha256_ctx_t tmp = *ctx;
    size_t idx = (size_t)((tmp.bitcount >> 3) & 0x3F);
    tmp.buffer[idx++] = 0x80;
    if (idx > 56) {
        memset(tmp.buffer + idx, 0, 64 - idx);
        sha256_transform(tmp.state, tmp.buffer);
        idx = 0;
    }
    memset(tmp.buffer + idx, 0, 56 - idx);
    for (int i = 0; i < 8; i++) {
        tmp.buffer[56 + i] = (uint8_t)(tmp.bitcount >> (56 - 8 * i));
    }
    sha256_transform(tmp.state, tmp.buffer);
    for (int i = 0; i < 8; i++) {
        out[4 * i]     = (uint8_t)(tmp.state[i] >> 24);
        out[4 * i + 1] = (uint8_t)(tmp.state[i] >> 16);
        out[4 * i + 2] = (uint8_t)(tmp.state[i] >> 8);
        out[4 * i + 3] = (uint8_t)(tmp.state[i]);
    }
}

static void sha256_oneshot(uint8_t out[32], const uint8_t *data, size_t len) {
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

static void hmac_sha256(uint8_t out[32], const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len) {
    uint8_t k_pad[64];
    uint8_t tk[32];
    if (key_len > 64) {
        sha256_oneshot(tk, key, key_len);
        key = tk;
        key_len = 32;
    }
    memset(k_pad, 0x36, 64);
    for (size_t i = 0; i < key_len; i++) k_pad[i] ^= key[i];

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, k_pad, 64);
    sha256_update(&ctx, data, data_len);
    uint8_t inner[32];
    sha256_final(&ctx, inner);

    memset(k_pad, 0x5c, 64);
    for (size_t i = 0; i < key_len; i++) k_pad[i] ^= key[i];

    sha256_init(&ctx);
    sha256_update(&ctx, k_pad, 64);
    sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, out);
}

static void hkdf_extract_sha256(uint8_t prk[32], const uint8_t salt[32],
                                const uint8_t *ikm, size_t ikm_len) {
    hmac_sha256(prk, salt, 32, ikm, ikm_len);
}

static void hkdf_expand_label(uint8_t *out, size_t out_len,
                              const uint8_t secret[32],
                              const char *label,
                              const uint8_t *context, size_t context_len) {
    uint8_t info[128];
    size_t label_len = strlen(label);
    size_t p = 0;
    info[p++] = (uint8_t)(out_len >> 8);
    info[p++] = (uint8_t)(out_len & 0xFF);
    info[p++] = (uint8_t)(6 + label_len);
    memcpy(info + p, "tls13 ", 6);
    p += 6;
    memcpy(info + p, label, label_len);
    p += label_len;
    info[p++] = (uint8_t)context_len;
    if (context_len > 0) {
        memcpy(info + p, context, context_len);
        p += context_len;
    }
    /* Since out_len <= 32 for all TLS 1.3 SHA-256 secrets/keys/IVs, 1 block suffices */
    info[p++] = 0x01;
    uint8_t tmp[32];
    hmac_sha256(tmp, secret, 32, info, p);
    memcpy(out, tmp, out_len);
}

/* =========================================================================
 * 2. RFC 7748 X25519 Scalar Multiplication
 * ========================================================================= */

typedef int64_t gf25519[16];

static void f25519_car(gf25519 o) {
    for (int i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        int64_t c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void f25519_sel(gf25519 p, gf25519 q, int b) {
    int64_t c = ~(b - 1);
    for (int i = 0; i < 16; i++) {
        int64_t t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void f25519_add(gf25519 o, const gf25519 a, const gf25519 b) {
    for (int i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

static void f25519_sub(gf25519 o, const gf25519 a, const gf25519 b) {
    for (int i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

static void f25519_mul(gf25519 o, const gf25519 a, const gf25519 b) {
    int64_t t[31] = {0};
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
            t[i + j] += a[i] * b[j];
        }
    }
    for (int i = 0; i < 15; i++) {
        t[i] += 38 * t[i + 16];
    }
    for (int i = 0; i < 16; i++) o[i] = t[i];
    f25519_car(o);
    f25519_car(o);
}

static void f25519_inv(gf25519 o, const gf25519 i) {
    gf25519 c;
    memcpy(c, i, sizeof(gf25519));
    for (int a = 253; a >= 0; a--) {
        f25519_mul(c, c, c);
        if (a != 2 && a != 4) f25519_mul(c, c, i);
    }
    memcpy(o, c, sizeof(gf25519));
}

static void x25519_scalarmult(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    uint8_t z[32];
    memcpy(z, scalar, 32);
    z[0] &= 248;
    z[31] = (z[31] & 127) | 64;

    gf25519 x, a = {0}, b = {0}, c = {0}, d = {0}, e, f;
    for (int i = 0; i < 16; i++) {
        x[i] = point[2 * i] + ((int64_t)point[2 * i + 1] << 8);
    }
    x[15] &= 0x7fff;
    a[0] = d[0] = 1;
    memcpy(b, x, sizeof(gf25519));

    for (int i = 254; i >= 0; i--) {
        int r = (z[i >> 3] >> (i & 7)) & 1;
        f25519_sel(a, b, r);
        f25519_sel(c, d, r);
        f25519_add(e, a, c);
        f25519_sub(a, a, c);
        f25519_add(c, b, d);
        f25519_sub(b, b, d);
        f25519_mul(d, e, e);
        f25519_mul(f, a, a);
        f25519_mul(a, c, a);
        f25519_mul(c, b, e);
        f25519_add(e, a, c);
        f25519_sub(a, a, c);
        f25519_mul(b, a, a);
        f25519_sub(c, d, f);
        gf25519 a24 = {0xdb41, 1};
        f25519_mul(a, c, a24);
        f25519_add(a, a, d);
        f25519_mul(c, c, a);
        f25519_mul(a, d, f);
        f25519_mul(d, b, x);
        f25519_mul(b, e, e);
        f25519_sel(a, b, r);
        f25519_sel(c, d, r);
    }

    f25519_inv(c, c);
    f25519_mul(a, a, c);
    f25519_car(a);
    f25519_car(a);
    f25519_car(a);

    gf25519 m;
    for (int j = 0; j < 2; j++) {
        m[0] = a[0] - 0xffed;
        for (int i = 1; i < 15; i++) {
            m[i] = a[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = a[15] - 0x7fff - ((m[14] >> 16) & 1);
        int b_flag = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        f25519_sel(a, m, 1 - b_flag);
    }
    for (int i = 0; i < 16; i++) {
        out[2 * i]     = (uint8_t)(a[i] & 0xff);
        out[2 * i + 1] = (uint8_t)(a[i] >> 8);
    }
}

/* =========================================================================
 * 3. RFC 8439 ChaCha20-Poly1305 AEAD (TLS_CHACHA20_POLY1305_SHA256)
 * ========================================================================= */

static inline uint32_t load32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

#define CHACHA_QR(a, b, c, d) do { \
    a += b; d ^= a; d = rotl32(d, 16); \
    c += d; b ^= c; b = rotl32(b, 12); \
    a += b; d ^= a; d = rotl32(d, 8);  \
    c += d; b ^= c; b = rotl32(b, 7);  \
} while (0)

static void chacha20_block(uint8_t out[64], const uint8_t key[32], uint32_t counter, const uint8_t nonce[12]) {
    uint32_t st[16] = {
        0x61707865UL, 0x3320646eUL, 0x79622d32UL, 0x6b206574UL,
        load32_le(key + 0),  load32_le(key + 4),  load32_le(key + 8),  load32_le(key + 12),
        load32_le(key + 16), load32_le(key + 20), load32_le(key + 24), load32_le(key + 28),
        counter, load32_le(nonce + 0), load32_le(nonce + 4), load32_le(nonce + 8)
    };
    uint32_t x[16];
    memcpy(x, st, sizeof(x));
    for (int i = 0; i < 10; i++) {
        CHACHA_QR(x[0], x[4], x[ 8], x[12]);
        CHACHA_QR(x[1], x[5], x[ 9], x[13]);
        CHACHA_QR(x[2], x[6], x[10], x[14]);
        CHACHA_QR(x[3], x[7], x[11], x[15]);
        CHACHA_QR(x[0], x[5], x[10], x[15]);
        CHACHA_QR(x[1], x[6], x[11], x[12]);
        CHACHA_QR(x[2], x[7], x[ 8], x[13]);
        CHACHA_QR(x[3], x[4], x[ 9], x[14]);
    }
    for (int i = 0; i < 16; i++) {
        store32_le(out + 4 * i, x[i] + st[i]);
    }
}

static void chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                         const uint8_t key[32], uint32_t counter, const uint8_t nonce[12]) {
    uint8_t block[64];
    while (len > 0) {
        chacha20_block(block, key, counter++, nonce);
        size_t chunk = len < 64 ? len : 64;
        for (size_t i = 0; i < chunk; i++) {
            out[i] = in[i] ^ block[i];
        }
        out += chunk;
        in += chunk;
        len -= chunk;
    }
}

typedef struct {
    uint32_t r[5];
    uint32_t pad[4];
    uint32_t h[5];
    uint8_t buf[16];
    size_t buf_used;
} poly1305_ctx_t;

static void poly1305_init(poly1305_ctx_t *ctx, const uint8_t key[32]) {
    ctx->r[0] = (load32_le(key +  0)     ) & 0x3ffffff;
    ctx->r[1] = (load32_le(key +  3) >> 2) & 0x3ffff03;
    ctx->r[2] = (load32_le(key +  6) >> 4) & 0x3ffc0ff;
    ctx->r[3] = (load32_le(key +  9) >> 6) & 0x3f03fff;
    ctx->r[4] = (load32_le(key + 12) >> 8) & 0x00fffff;

    ctx->pad[0] = load32_le(key + 16);
    ctx->pad[1] = load32_le(key + 20);
    ctx->pad[2] = load32_le(key + 24);
    ctx->pad[3] = load32_le(key + 28);

    memset(ctx->h, 0, sizeof(ctx->h));
    ctx->buf_used = 0;
}

static void poly1305_block(poly1305_ctx_t *ctx, const uint8_t b[16], uint32_t hibit) {
    uint32_t r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2], r3 = ctx->r[3], r4 = ctx->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

    uint32_t h0 = ctx->h[0] + (load32_le(b +  0) & 0x3ffffff);
    uint32_t h1 = ctx->h[1] + ((load32_le(b +  3) >> 2) & 0x3ffffff);
    uint32_t h2 = ctx->h[2] + ((load32_le(b +  6) >> 4) & 0x3ffffff);
    uint32_t h3 = ctx->h[3] + ((load32_le(b +  9) >> 6) & 0x3ffffff);
    uint32_t h4 = ctx->h[4] + (load32_le(b + 12) >> 8) + (hibit << 24);

    uint64_t d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
    uint64_t d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
    uint64_t d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
    uint64_t d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
    uint64_t d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;

    uint32_t c;
    c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff; d1 += c;
    c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff; d2 += c;
    c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff; d3 += c;
    c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff; d4 += c;
    c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    ctx->h[0] = h0; ctx->h[1] = h1; ctx->h[2] = h2; ctx->h[3] = h3; ctx->h[4] = h4;
}

static void poly1305_update(poly1305_ctx_t *ctx, const uint8_t *m, size_t len) {
    if (ctx->buf_used > 0) {
        size_t take = 16 - ctx->buf_used;
        if (take > len) take = len;
        memcpy(ctx->buf + ctx->buf_used, m, take);
        ctx->buf_used += take;
        m += take;
        len -= take;
        if (ctx->buf_used == 16) {
            poly1305_block(ctx, ctx->buf, 1);
            ctx->buf_used = 0;
        }
    }
    while (len >= 16) {
        poly1305_block(ctx, m, 1);
        m += 16;
        len -= 16;
    }
    if (len > 0) {
        memcpy(ctx->buf, m, len);
        ctx->buf_used = len;
    }
}

static void poly1305_final(poly1305_ctx_t *ctx, uint8_t mac[16]) {
    if (ctx->buf_used > 0) {
        ctx->buf[ctx->buf_used] = 1;
        memset(ctx->buf + ctx->buf_used + 1, 0, 16 - ctx->buf_used - 1);
        poly1305_block(ctx, ctx->buf, 0);
    }
    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2], h3 = ctx->h[3], h4 = ctx->h[4];
    uint32_t c;
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1UL << 26);

    uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    h0 = (h0      ) | (h1 << 26);
    h1 = (h1 >>  6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 <<  8);

    uint64_t f;
    f = (uint64_t)h0 + ctx->pad[0];              h0 = (uint32_t)f;
    f = (uint64_t)h1 + ctx->pad[1] + (f >> 32);  h1 = (uint32_t)f;
    f = (uint64_t)h2 + ctx->pad[2] + (f >> 32);  h2 = (uint32_t)f;
    f = (uint64_t)h3 + ctx->pad[3] + (f >> 32);  h3 = (uint32_t)f;

    store32_le(mac +  0, h0);
    store32_le(mac +  4, h1);
    store32_le(mac +  8, h2);
    store32_le(mac + 12, h3);
}

static void chacha20_poly1305_compute_tag(uint8_t tag[16],
                                          const uint8_t poly_key[32],
                                          const uint8_t *aad, size_t aad_len,
                                          const uint8_t *ct, size_t ct_len) {
    static const uint8_t zeros[16] = {0};
    poly1305_ctx_t pctx;
    poly1305_init(&pctx, poly_key);
    poly1305_update(&pctx, aad, aad_len);
    if (aad_len % 16 != 0) {
        poly1305_update(&pctx, zeros, 16 - (aad_len % 16));
    }
    poly1305_update(&pctx, ct, ct_len);
    if (ct_len % 16 != 0) {
        poly1305_update(&pctx, zeros, 16 - (ct_len % 16));
    }
    uint8_t lens[16];
    for (int i = 0; i < 8; i++) {
        lens[i]     = (uint8_t)((uint64_t)aad_len >> (8 * i));
        lens[8 + i] = (uint8_t)((uint64_t)ct_len >> (8 * i));
    }
    poly1305_update(&pctx, lens, 16);
    poly1305_final(&pctx, tag);
}

static void tls13_make_nonce(uint8_t nonce[12], const uint8_t iv[12], uint64_t seq) {
    memcpy(nonce, iv, 12);
    for (int i = 0; i < 8; i++) {
        nonce[11 - i] ^= (uint8_t)(seq >> (8 * i));
    }
}

static void chacha20_poly1305_encrypt(uint8_t *ct, uint8_t tag[16],
                                      const uint8_t *pt, size_t pt_len,
                                      const uint8_t *aad, size_t aad_len,
                                      const uint8_t key[32], const uint8_t nonce[12]) {
    uint8_t poly_block[64];
    chacha20_block(poly_block, key, 0, nonce);
    chacha20_xor(ct, pt, pt_len, key, 1, nonce);
    chacha20_poly1305_compute_tag(tag, poly_block, aad, aad_len, ct, pt_len);
}

static int chacha20_poly1305_decrypt(uint8_t *pt,
                                     const uint8_t *ct, size_t ct_len,
                                     const uint8_t tag[16],
                                     const uint8_t *aad, size_t aad_len,
                                     const uint8_t key[32], const uint8_t nonce[12]) {
    uint8_t poly_block[64];
    uint8_t calc_tag[16];
    chacha20_block(poly_block, key, 0, nonce);
    chacha20_poly1305_compute_tag(calc_tag, poly_block, aad, aad_len, ct, ct_len);
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= calc_tag[i] ^ tag[i];
    if (diff != 0) return -1;
    chacha20_xor(pt, ct, ct_len, key, 1, nonce);
    return 0;
}

/* =========================================================================
 * 4. Platform Crypto Callbacks (RNG, ECDSA-P256 Sign, X.509 Verify)
 * ========================================================================= */

static void pq_random_bytes(uint8_t *buf, size_t len) {
#ifdef ESP_PLATFORM
    esp_fill_random(buf, len);
#else
    RAND_bytes(buf, (int)len);
#endif
}

static int pq_ecdsa_p256_sign_sha256(uint8_t *sig, size_t sig_max, size_t *sig_len,
                                     const uint8_t *msg, size_t msg_len) {
    uint8_t digest[32];
    sha256_oneshot(digest, msg, msg_len);
#ifdef ESP_PLATFORM
    psa_crypto_init();
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    int rc = mbedtls_pk_parse_key(&pk, SERVER_KEY_DER, sizeof(SERVER_KEY_DER), NULL, 0);
    if (rc != 0) {
        PQ_LOGE("mbedtls_pk_parse_key failed: -0x%04x", -rc);
        mbedtls_pk_free(&pk);
        return -1;
    }
    rc = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, digest, 32, sig, sig_max, sig_len);
    pq_sample_heap();
    mbedtls_pk_free(&pk);
    if (rc != 0) {
        PQ_LOGE("mbedtls_pk_sign failed: -0x%04x", -rc);
        return -1;
    }
    return 0;
#else
    const unsigned char *p = SERVER_KEY_DER;
    EVP_PKEY *pkey = d2i_AutoPrivateKey(NULL, &p, sizeof(SERVER_KEY_DER));
    if (!pkey) return -1;
    *sig_len = sig_max;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    int ok = (EVP_DigestSignInit(mctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
              EVP_DigestSign(mctx, sig, sig_len, msg, msg_len) == 1);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return ok ? 0 : -1;
#endif
}

static int pq_verify_client_cert_and_sig(const uint8_t *cert_der, size_t cert_len,
                                         uint16_t sig_scheme,
                                         const uint8_t *sig, size_t sig_len,
                                         const uint8_t *cv_msg, size_t cv_msg_len,
                                         char client_cn[64]) {
    if (sig_scheme != 0x0403) { /* ecdsa_secp256r1_sha256 */
        PQ_LOGE("Unsupported client signature scheme: 0x%04x", sig_scheme);
        return -1;
    }
#ifdef ESP_PLATFORM
    psa_crypto_init();
    mbedtls_x509_crt ca, cli;
    mbedtls_x509_crt_init(&ca);
    mbedtls_x509_crt_init(&cli);

    int rc = mbedtls_x509_crt_parse_der(&ca, CA_CERT_DER, sizeof(CA_CERT_DER));
    if (rc != 0) {
        PQ_LOGE("Failed to parse CA cert: -0x%04x", -rc);
        mbedtls_x509_crt_free(&ca);
        mbedtls_x509_crt_free(&cli);
        return -1;
    }
    rc = mbedtls_x509_crt_parse_der(&cli, cert_der, cert_len);
    if (rc != 0) {
        PQ_LOGE("Failed to parse client cert: -0x%04x", -rc);
        mbedtls_x509_crt_free(&ca);
        mbedtls_x509_crt_free(&cli);
        return -1;
    }
    uint32_t flags = 0;
    rc = mbedtls_x509_crt_verify(&cli, &ca, NULL, NULL, &flags, NULL, NULL);
    if (rc != 0 || flags != 0) {
        PQ_LOGE("Client X.509 certificate verification failed! rc=-0x%04x flags=0x%08lx",
                -rc, (unsigned long)flags);
        mbedtls_x509_crt_free(&ca);
        mbedtls_x509_crt_free(&cli);
        return -1;
    }
    /* Extract Subject CN if available */
    client_cn[0] = '\0';
    const mbedtls_x509_name *name = &cli.subject;
    while (name != NULL) {
        if (name->oid.len == 3 && memcmp(name->oid.p, "\x55\x04\x03", 3) == 0) {
            size_t copy_len = name->val.len < 63 ? name->val.len : 63;
            memcpy(client_cn, name->val.p, copy_len);
            client_cn[copy_len] = '\0';
            break;
        }
        name = name->next;
    }

    uint8_t digest[32];
    sha256_oneshot(digest, cv_msg, cv_msg_len);
    rc = mbedtls_pk_verify(&cli.pk, MBEDTLS_MD_SHA256, digest, 32, sig, sig_len);
    pq_sample_heap();
    mbedtls_x509_crt_free(&ca);
    mbedtls_x509_crt_free(&cli);
    if (rc != 0) {
        PQ_LOGE("Client CertificateVerify signature check failed: -0x%04x", -rc);
        return -1;
    }
    return 0;
#else
    const unsigned char *p_ca = CA_CERT_DER;
    X509 *ca_x509 = d2i_X509(NULL, &p_ca, sizeof(CA_CERT_DER));
    const unsigned char *p_cli = cert_der;
    X509 *cli_x509 = d2i_X509(NULL, &p_cli, (long)cert_len);
    if (!ca_x509 || !cli_x509) {
        if (ca_x509) X509_free(ca_x509);
        if (cli_x509) X509_free(cli_x509);
        return -1;
    }
    X509_STORE *store = X509_STORE_new();
    X509_STORE_add_cert(store, ca_x509);
    X509_STORE_CTX *sctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(sctx, store, cli_x509, NULL);
    int vfy = X509_verify_cert(sctx);
    X509_STORE_CTX_free(sctx);
    X509_STORE_free(store);
    X509_free(ca_x509);
    if (vfy != 1) {
        X509_free(cli_x509);
        return -1;
    }
    X509_NAME_get_text_by_NID(X509_get_subject_name(cli_x509), NID_commonName, client_cn, 64);
    EVP_PKEY *pub = X509_get_pubkey(cli_x509);
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    int ok = (EVP_DigestVerifyInit(mctx, NULL, EVP_sha256(), NULL, pub) == 1 &&
              EVP_DigestVerify(mctx, sig, sig_len, cv_msg, cv_msg_len) == 1);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pub);
    X509_free(cli_x509);
    return ok ? 0 : -1;
#endif
}

/* =========================================================================
 * 5. Socket I/O and TLS 1.3 Record Helpers
 * ========================================================================= */

static int read_exact(int fd, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, buf + got, len - got, 0);
        if (n == 0) return 0;
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        got += (size_t)n;
    }
    return (int)got;
}

static int write_exact(int fd, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)n;
    }
    return (int)sent;
}

static int tls13_send_encrypted_record(int fd,
                                       const uint8_t key[32],
                                       const uint8_t iv[12],
                                       uint64_t *seq,
                                       uint8_t inner_content_type,
                                       const uint8_t *payload,
                                       size_t payload_len) {
    if (payload_len > 2048) return -1;
    uint8_t record[5 + 2048 + 1 + 16];
    size_t inner_len = payload_len + 1;
    size_t rec_payload_len = inner_len + 16;

    record[0] = 0x17; /* application_data outer wrapper */
    record[1] = 0x03;
    record[2] = 0x03;
    record[3] = (uint8_t)(rec_payload_len >> 8);
    record[4] = (uint8_t)(rec_payload_len & 0xFF);

    /* Construct inner plaintext in-place before encrypting */
    memcpy(record + 5, payload, payload_len);
    record[5 + payload_len] = inner_content_type;

    uint8_t nonce[12];
    tls13_make_nonce(nonce, iv, *seq);
    (*seq)++;

    uint8_t tag[16];
    chacha20_poly1305_encrypt(record + 5, tag, record + 5, inner_len, record, 5, key, nonce);
    memcpy(record + 5 + inner_len, tag, 16);

    return write_exact(fd, record, 5 + rec_payload_len) < 0 ? -1 : 0;
}

static int tls13_recv_encrypted_record(int fd,
                                       const uint8_t key[32],
                                       const uint8_t iv[12],
                                       uint64_t *seq,
                                       uint8_t *inner_content_type,
                                       uint8_t *out_buf,
                                       size_t max_len,
                                       size_t *out_len) {
    uint8_t hdr[5];
    uint8_t cipher_buf[2048 + 32];
    for (;;) {
        int r = read_exact(fd, hdr, 5);
        if (r <= 0) return r;
        uint8_t rtype = hdr[0];
        size_t rlen = ((size_t)hdr[3] << 8) | hdr[4];

        /* Ignore TLS 1.3 dummy ChangeCipherSpec records (0x14) */
        if (rtype == 0x14) {
            if (rlen > sizeof(cipher_buf)) return -1;
            if (read_exact(fd, cipher_buf, rlen) <= 0) return -1;
            continue;
        }
        if (rtype != 0x17 || rlen < 17 || rlen > sizeof(cipher_buf)) {
            PQ_LOGE("Unexpected TLS record type=0x%02x len=%zu", rtype, rlen);
            return -1;
        }
        if (read_exact(fd, cipher_buf, rlen) <= 0) return -1;

        size_t inner_len = rlen - 16;
        uint8_t nonce[12];
        tls13_make_nonce(nonce, iv, *seq);
        (*seq)++;

        if (chacha20_poly1305_decrypt(cipher_buf, cipher_buf, inner_len,
                                      cipher_buf + inner_len, hdr, 5, key, nonce) != 0) {
            PQ_LOGE("ChaCha20-Poly1305 record authentication failed!");
            return -1;
        }
        /* Strip zero padding from end of TLSInnerPlaintext */
        while (inner_len > 0 && cipher_buf[inner_len - 1] == 0x00) {
            inner_len--;
        }
        if (inner_len == 0) return -1;
        *inner_content_type = cipher_buf[inner_len - 1];
        size_t pt_len = inner_len - 1;
        if (pt_len > max_len) return -1;
        memcpy(out_buf, cipher_buf, pt_len);
        *out_len = pt_len;
        return 1;
    }
}

/* =========================================================================
 * 6. TLS 1.3 Server Handshake (X25519MLKEM768 + ChaCha20-Poly1305 + mTLS)
 * ========================================================================= */

/* Static buffer for handshake messages to minimize stack footprint */
static struct {
    uint8_t io_buf[2560];
    uint8_t client_ek[MLKEM768_EK_BYTES];
    uint8_t client_x25519[32];
    uint8_t mlkem_ct[MLKEM768_CT_BYTES];
    uint8_t server_x25519_pub[32];
    uint8_t client_cert_der[1024];
    size_t client_cert_len;
} s_hs;

int pq_mtls_server_handshake(pq_mtls_conn_t *conn, int fd) {
    memset(conn, 0, sizeof(*conn));
    conn->fd = fd;
    conn->hs_static_bytes = sizeof(*conn) + sizeof(s_hs);
#ifdef ESP_PLATFORM
    size_t heap_before = esp_get_free_heap_size();
    s_hs_min_free_heap = heap_before;
#endif

    sha256_ctx_t transcript;
    sha256_init(&transcript);

    /* --- Step 1: Read & Parse ClientHello --- */
    uint8_t rec_hdr[5];
    if (read_exact(fd, rec_hdr, 5) <= 0) {
        PQ_LOGE("Failed to read ClientHello record header");
        return -1;
    }
    if (rec_hdr[0] != 0x16) {
        PQ_LOGE("Expected Handshake record (0x16), got 0x%02x", rec_hdr[0]);
        return -1;
    }
    size_t rec_len = ((size_t)rec_hdr[3] << 8) | rec_hdr[4];
    if (rec_len < 42 || rec_len > sizeof(s_hs.io_buf)) {
        PQ_LOGE("Invalid ClientHello record length: %zu", rec_len);
        return -1;
    }
    if (read_exact(fd, s_hs.io_buf, rec_len) <= 0) {
        PQ_LOGE("Failed to read ClientHello body");
        return -1;
    }

    if (s_hs.io_buf[0] != 0x01) {
        PQ_LOGE("Expected ClientHello (0x01), got 0x%02x", s_hs.io_buf[0]);
        return -1;
    }
    size_t ch_len = ((size_t)s_hs.io_buf[1] << 16) |
                    ((size_t)s_hs.io_buf[2] << 8) |
                    s_hs.io_buf[3];
    if (4 + ch_len != rec_len) {
        PQ_LOGE("ClientHello length mismatch");
        return -1;
    }

    /* Update transcript hash with ClientHello */
    sha256_update(&transcript, s_hs.io_buf, rec_len);

    const uint8_t *p = s_hs.io_buf + 4;
    const uint8_t *end = s_hs.io_buf + rec_len;

    p += 2 + 32; /* Skip legacy_version (2) + client_random (32) */
    if (p + 1 > end) return -1;
    uint8_t sid_len = *p++;
    if (sid_len > 32 || p + sid_len > end) return -1;
    uint8_t session_id[32];
    memcpy(session_id, p, sid_len);
    p += sid_len;

    /* Cipher suites */
    if (p + 2 > end) return -1;
    size_t cs_len = ((size_t)p[0] << 8) | p[1];
    p += 2;
    if (p + cs_len > end) return -1;
    int found_chacha = 0;
    for (size_t i = 0; i + 1 < cs_len; i += 2) {
        uint16_t cs = ((uint16_t)p[i] << 8) | p[i + 1];
        if (cs == TLS13_CIPHER_CHACHA20_POLY1305_SHA256) {
            found_chacha = 1;
        }
    }
    p += cs_len;
    if (!found_chacha) {
        PQ_LOGE("Client did not offer TLS_CHACHA20_POLY1305_SHA256 (0x1303)");
        return -1;
    }

    /* Compression methods */
    if (p + 1 > end) return -1;
    uint8_t comp_len = *p++;
    if (p + comp_len > end) return -1;
    p += comp_len;

    /* Extensions */
    if (p + 2 > end) return -1;
    size_t exts_len = ((size_t)p[0] << 8) | p[1];
    p += 2;
    if (p + exts_len > end) return -1;
    const uint8_t *exts_end = p + exts_len;

    int found_tls13 = 0;
    int found_pq_share = 0;

    while (p + 4 <= exts_end) {
        uint16_t ext_type = ((uint16_t)p[0] << 8) | p[1];
        size_t ext_len = ((size_t)p[2] << 8) | p[3];
        p += 4;
        if (p + ext_len > exts_end) return -1;

        if (ext_type == 0x002b) { /* supported_versions */
            if (ext_len >= 1) {
                size_t vlen = p[0];
                for (size_t i = 1; i + 1 <= 1 + vlen && i + 1 <= ext_len; i += 2) {
                    uint16_t v = ((uint16_t)p[i] << 8) | p[i + 1];
                    if (v == 0x0304) found_tls13 = 1;
                }
            }
        } else if (ext_type == 0x0033) { /* key_share */
            if (ext_len >= 2) {
                size_t ks_list_len = ((size_t)p[0] << 8) | p[1];
                const uint8_t *kp = p + 2;
                const uint8_t *kend = p + 2 + ks_list_len;
                if (kend <= p + ext_len) {
                    while (kp + 4 <= kend) {
                        uint16_t grp = ((uint16_t)kp[0] << 8) | kp[1];
                        size_t klen = ((size_t)kp[2] << 8) | kp[3];
                        kp += 4;
                        if (kp + klen > kend) break;
                        if (grp == TLS13_GROUP_X25519MLKEM768 && klen == (MLKEM768_EK_BYTES + 32)) {
                            memcpy(s_hs.client_ek, kp, MLKEM768_EK_BYTES);
                            memcpy(s_hs.client_x25519, kp + MLKEM768_EK_BYTES, 32);
                            found_pq_share = 1;
                            break;
                        }
                        kp += klen;
                    }
                }
            }
        }
        p += ext_len;
    }

    if (!found_tls13 || !found_pq_share) {
        PQ_LOGE("ClientHello missing TLS 1.3 (%d) or X25519MLKEM768 key_share (%d)",
                found_tls13, found_pq_share);
        return -1;
    }

    /* --- Step 2: Compute X25519MLKEM768 Hybrid Key Exchange --- */
    uint8_t hybrid_shared_secret[64];
    uint8_t mlkem_coins[32];
    pq_random_bytes(mlkem_coins, 32);

    if (mlkem768_encaps(s_hs.mlkem_ct, hybrid_shared_secret, s_hs.client_ek, mlkem_coins) != 0) {
        PQ_LOGE("ML-KEM-768 encapsulation failed (invalid client ek)");
        return -1;
    }

    uint8_t server_x25519_priv[32];
    pq_random_bytes(server_x25519_priv, 32);
    static const uint8_t x25519_basepoint[32] = {9};
    x25519_scalarmult(s_hs.server_x25519_pub, server_x25519_priv, x25519_basepoint);
    x25519_scalarmult(hybrid_shared_secret + 32, server_x25519_priv, s_hs.client_x25519);

    /* Reject all-zero X25519 shared secret per RFC 7748 */
    uint8_t nz = 0;
    for (int i = 0; i < 32; i++) nz |= hybrid_shared_secret[32 + i];
    if (nz == 0) return -1;

    /* --- Step 3: Build & Send ServerHello --- */
    uint8_t *sh_rec = s_hs.io_buf;
    uint8_t *sh = sh_rec + 5;
    size_t pos = 4; /* Reserve 4 bytes for Handshake header */

    /* legacy_version = 0x0303 */
    sh[pos++] = 0x03;
    sh[pos++] = 0x03;
    /* server_random (32 bytes) */
    pq_random_bytes(sh + pos, 32);
    pos += 32;
    /* legacy_session_id_echo */
    sh[pos++] = sid_len;
    memcpy(sh + pos, session_id, sid_len);
    pos += sid_len;
    /* cipher_suite = TLS_CHACHA20_POLY1305_SHA256 (0x1303) */
    sh[pos++] = 0x13;
    sh[pos++] = 0x03;
    /* legacy_compression_method = 0 */
    sh[pos++] = 0x00;

    /* Extensions length: supported_versions (6B) + key_share (8 + 1120 = 1128B) = 1134B */
    size_t sh_exts_len = 6 + 8 + MLKEM768_CT_BYTES + 32;
    sh[pos++] = (uint8_t)(sh_exts_len >> 8);
    sh[pos++] = (uint8_t)(sh_exts_len & 0xFF);

    /* Extension: supported_versions (0x002b) -> 0x0304 */
    sh[pos++] = 0x00; sh[pos++] = 0x2b;
    sh[pos++] = 0x00; sh[pos++] = 0x02;
    sh[pos++] = 0x03; sh[pos++] = 0x04;

    /* Extension: key_share (0x0033) -> group 0x11EC (X25519MLKEM768) */
    size_t ks_kex_len = MLKEM768_CT_BYTES + 32; /* 1120 */
    size_t ks_ext_len = 4 + ks_kex_len;         /* 1124 */
    sh[pos++] = 0x00; sh[pos++] = 0x33;
    sh[pos++] = (uint8_t)(ks_ext_len >> 8);
    sh[pos++] = (uint8_t)(ks_ext_len & 0xFF);
    sh[pos++] = (uint8_t)(TLS13_GROUP_X25519MLKEM768 >> 8);
    sh[pos++] = (uint8_t)(TLS13_GROUP_X25519MLKEM768 & 0xFF);
    sh[pos++] = (uint8_t)(ks_kex_len >> 8);
    sh[pos++] = (uint8_t)(ks_kex_len & 0xFF);
    memcpy(sh + pos, s_hs.mlkem_ct, MLKEM768_CT_BYTES);
    pos += MLKEM768_CT_BYTES;
    memcpy(sh + pos, s_hs.server_x25519_pub, 32);
    pos += 32;

    size_t sh_body_len = pos - 4;
    sh[0] = 0x02; /* ServerHello */
    sh[1] = (uint8_t)(sh_body_len >> 16);
    sh[2] = (uint8_t)(sh_body_len >> 8);
    sh[3] = (uint8_t)(sh_body_len & 0xFF);

    sh_rec[0] = 0x16;
    sh_rec[1] = 0x03;
    sh_rec[2] = 0x03;
    sh_rec[3] = (uint8_t)(pos >> 8);
    sh_rec[4] = (uint8_t)(pos & 0xFF);

    if (write_exact(fd, sh_rec, 5 + pos) < 0) return -1;
    sha256_update(&transcript, sh, pos);

    /* --- Step 4: Derive TLS 1.3 Handshake Traffic Keys --- */
    static const uint8_t zero32[32] = {0};
    uint8_t empty_hash[32];
    sha256_oneshot(empty_hash, NULL, 0);

    uint8_t early_secret[32];
    uint8_t derived_secret[32];
    uint8_t handshake_secret[32];
    hkdf_extract_sha256(early_secret, zero32, zero32, 32);
    hkdf_expand_label(derived_secret, 32, early_secret, "derived", empty_hash, 32);
    hkdf_extract_sha256(handshake_secret, derived_secret, hybrid_shared_secret, 64);

    uint8_t hello_hash[32];
    sha256_final(&transcript, hello_hash);

    uint8_t c_hs_traffic[32], s_hs_traffic[32];
    hkdf_expand_label(c_hs_traffic, 32, handshake_secret, "c hs traffic", hello_hash, 32);
    hkdf_expand_label(s_hs_traffic, 32, handshake_secret, "s hs traffic", hello_hash, 32);

    uint8_t c_hs_key[32], c_hs_iv[12], s_hs_key[32], s_hs_iv[12];
    uint64_t c_hs_seq = 0, s_hs_seq = 0;
    hkdf_expand_label(c_hs_key, 32, c_hs_traffic, "key", NULL, 0);
    hkdf_expand_label(c_hs_iv,  12, c_hs_traffic, "iv",  NULL, 0);
    hkdf_expand_label(s_hs_key, 32, s_hs_traffic, "key", NULL, 0);
    hkdf_expand_label(s_hs_iv,  12, s_hs_traffic, "iv",  NULL, 0);

    /* --- Step 5: Send EncryptedExtensions, CertificateRequest, Certificate, CertificateVerify, Finished --- */

    /* 5a. EncryptedExtensions (0x08) */
    uint8_t ee_msg[6] = {0x08, 0x00, 0x00, 0x02, 0x00, 0x00};
    sha256_update(&transcript, ee_msg, sizeof(ee_msg));
    if (tls13_send_encrypted_record(fd, s_hs_key, s_hs_iv, &s_hs_seq, 0x16, ee_msg, sizeof(ee_msg)) != 0) {
        return -1;
    }

    /* 5b. CertificateRequest (0x0d) for mTLS */
    uint8_t cr_msg[] = {
        0x0d, 0x00, 0x00, 0x0d, /* Handshake type 13, length 13 */
        0x00,                   /* certificate_request_context length = 0 */
        0x00, 0x0a,             /* extensions length = 10 */
        0x00, 0x0d,             /* signature_algorithms (13) */
        0x00, 0x06,             /* ext data length = 6 */
        0x00, 0x04,             /* list length = 4 */
        0x04, 0x03,             /* ecdsa_secp256r1_sha256 */
        0x08, 0x07              /* ed25519 */
    };
    sha256_update(&transcript, cr_msg, sizeof(cr_msg));
    if (tls13_send_encrypted_record(fd, s_hs_key, s_hs_iv, &s_hs_seq, 0x16, cr_msg, sizeof(cr_msg)) != 0) {
        return -1;
    }

    /* 5c. Server Certificate (0x0b) */
    size_t cert_len = sizeof(SERVER_CERT_DER);
    size_t cert_list_len = 3 + cert_len + 2;
    size_t cert_msg_body_len = 1 + 3 + cert_list_len;
    uint8_t *cert_msg = s_hs.io_buf;
    cert_msg[0] = 0x0b;
    cert_msg[1] = (uint8_t)(cert_msg_body_len >> 16);
    cert_msg[2] = (uint8_t)(cert_msg_body_len >> 8);
    cert_msg[3] = (uint8_t)(cert_msg_body_len & 0xFF);
    cert_msg[4] = 0x00; /* certificate_request_context = 0 */
    cert_msg[5] = (uint8_t)(cert_list_len >> 16);
    cert_msg[6] = (uint8_t)(cert_list_len >> 8);
    cert_msg[7] = (uint8_t)(cert_list_len & 0xFF);
    cert_msg[8] = (uint8_t)(cert_len >> 16);
    cert_msg[9] = (uint8_t)(cert_len >> 8);
    cert_msg[10] = (uint8_t)(cert_len & 0xFF);
    memcpy(cert_msg + 11, SERVER_CERT_DER, cert_len);
    cert_msg[11 + cert_len] = 0x00; /* extensions = 0 */
    cert_msg[12 + cert_len] = 0x00;
    size_t cert_msg_total = 4 + cert_msg_body_len;

    sha256_update(&transcript, cert_msg, cert_msg_total);
    if (tls13_send_encrypted_record(fd, s_hs_key, s_hs_iv, &s_hs_seq, 0x16, cert_msg, cert_msg_total) != 0) {
        return -1;
    }

    /* 5d. Server CertificateVerify (0x0f) */
    uint8_t thash_before_cv[32];
    sha256_final(&transcript, thash_before_cv);

    uint8_t cv_to_sign[64 + 34 + 32];
    memset(cv_to_sign, 0x20, 64);
    memcpy(cv_to_sign + 64, "TLS 1.3, server CertificateVerify", 34); /* includes NUL terminator */
    memcpy(cv_to_sign + 98, thash_before_cv, 32);

    uint8_t sig_buf[128];
    size_t sig_len = 0;
    if (pq_ecdsa_p256_sign_sha256(sig_buf, sizeof(sig_buf), &sig_len, cv_to_sign, sizeof(cv_to_sign)) != 0) {
        return -1;
    }

    uint8_t cv_msg[4 + 4 + 128];
    size_t cv_body_len = 4 + sig_len;
    cv_msg[0] = 0x0f;
    cv_msg[1] = 0x00;
    cv_msg[2] = (uint8_t)(cv_body_len >> 8);
    cv_msg[3] = (uint8_t)(cv_body_len & 0xFF);
    cv_msg[4] = 0x04; /* ecdsa_secp256r1_sha256 (0x0403) */
    cv_msg[5] = 0x03;
    cv_msg[6] = (uint8_t)(sig_len >> 8);
    cv_msg[7] = (uint8_t)(sig_len & 0xFF);
    memcpy(cv_msg + 8, sig_buf, sig_len);

    sha256_update(&transcript, cv_msg, 4 + cv_body_len);
    if (tls13_send_encrypted_record(fd, s_hs_key, s_hs_iv, &s_hs_seq, 0x16, cv_msg, 4 + cv_body_len) != 0) {
        return -1;
    }

    /* 5e. Server Finished (0x14) */
    uint8_t thash_before_sfin[32];
    sha256_final(&transcript, thash_before_sfin);

    uint8_t s_fin_key[32];
    hkdf_expand_label(s_fin_key, 32, s_hs_traffic, "finished", NULL, 0);
    uint8_t s_fin_msg[4 + 32];
    s_fin_msg[0] = 0x14;
    s_fin_msg[1] = 0x00;
    s_fin_msg[2] = 0x00;
    s_fin_msg[3] = 32;
    hmac_sha256(s_fin_msg + 4, s_fin_key, 32, thash_before_sfin, 32);

    sha256_update(&transcript, s_fin_msg, sizeof(s_fin_msg));
    if (tls13_send_encrypted_record(fd, s_hs_key, s_hs_iv, &s_hs_seq, 0x16, s_fin_msg, sizeof(s_fin_msg)) != 0) {
        return -1;
    }

    /* --- Step 6: Derive Application Traffic Secrets (from Server Finished transcript) --- */
    uint8_t thash_after_sfin[32];
    sha256_final(&transcript, thash_after_sfin);

    uint8_t derived_secret2[32], master_secret[32];
    hkdf_expand_label(derived_secret2, 32, handshake_secret, "derived", empty_hash, 32);
    hkdf_extract_sha256(master_secret, derived_secret2, zero32, 32);

    uint8_t c_ap_traffic[32], s_ap_traffic[32];
    hkdf_expand_label(c_ap_traffic, 32, master_secret, "c ap traffic", thash_after_sfin, 32);
    hkdf_expand_label(s_ap_traffic, 32, master_secret, "s ap traffic", thash_after_sfin, 32);

    hkdf_expand_label(conn->c_ap_key, 32, c_ap_traffic, "key", NULL, 0);
    hkdf_expand_label(conn->c_ap_iv,  12, c_ap_traffic, "iv",  NULL, 0);
    hkdf_expand_label(conn->s_ap_key, 32, s_ap_traffic, "key", NULL, 0);
    hkdf_expand_label(conn->s_ap_iv,  12, s_ap_traffic, "iv",  NULL, 0);
    conn->c_ap_seq = 0;
    conn->s_ap_seq = 0;

    /* --- Step 7: Receive & Verify Client Certificate, CertificateVerify, and Finished --- */
    int got_client_cert = 0;
    int got_client_cv = 0;
    int got_client_fin = 0;
    size_t hs_accum = 0;

    while (!got_client_fin) {
        uint8_t ctype = 0;
        size_t pt_len = 0;
        if (hs_accum >= sizeof(s_hs.io_buf)) return -1;
        int r = tls13_recv_encrypted_record(fd, c_hs_key, c_hs_iv, &c_hs_seq,
                                            &ctype, s_hs.io_buf + hs_accum,
                                            sizeof(s_hs.io_buf) - hs_accum, &pt_len);
        if (r <= 0 || ctype != 0x16) {
            PQ_LOGE("Failed reading client handshake record (r=%d ctype=0x%02x)", r, ctype);
            return -1;
        }
        hs_accum += pt_len;

        size_t off = 0;
        while (off + 4 <= hs_accum) {
            uint8_t msg_type = s_hs.io_buf[off];
            size_t msg_len = ((size_t)s_hs.io_buf[off + 1] << 16) |
                             ((size_t)s_hs.io_buf[off + 2] << 8) |
                             s_hs.io_buf[off + 3];
            if (off + 4 + msg_len > hs_accum) {
                break; /* Need more records to complete this handshake message */
            }
            const uint8_t *msg_ptr = s_hs.io_buf + off;
            const uint8_t *body = msg_ptr + 4;

            if (msg_type == 0x0b && !got_client_cert) {
                /* Client Certificate */
                if (msg_len < 4) return -1;
                uint8_t ctx_len = body[0];
                if (1 + ctx_len + 3 > msg_len) return -1;
                const uint8_t *clist = body + 1 + ctx_len;
                size_t clist_len = ((size_t)clist[0] << 16) | ((size_t)clist[1] << 8) | clist[2];
                if (clist_len < 5 || 1 + ctx_len + 3 + clist_len > msg_len) {
                    PQ_LOGE("Client sent empty or malformed certificate list (mTLS required!)");
                    return -1;
                }
                const uint8_t *c_entry = clist + 3;
                size_t c_der_len = ((size_t)c_entry[0] << 16) | ((size_t)c_entry[1] << 8) | c_entry[2];
                if (3 + c_der_len + 2 > clist_len || c_der_len > sizeof(s_hs.client_cert_der)) {
                    return -1;
                }
                memcpy(s_hs.client_cert_der, c_entry + 3, c_der_len);
                s_hs.client_cert_len = c_der_len;
                sha256_update(&transcript, msg_ptr, 4 + msg_len);
                got_client_cert = 1;
            } else if (msg_type == 0x0f && got_client_cert && !got_client_cv) {
                /* Client CertificateVerify */
                if (msg_len < 4) return -1;
                uint16_t sig_scheme = ((uint16_t)body[0] << 8) | body[1];
                size_t c_sig_len = ((size_t)body[2] << 8) | body[3];
                if (4 + c_sig_len != msg_len) return -1;

                uint8_t thash_ccert[32];
                sha256_final(&transcript, thash_ccert);

                uint8_t c_cv_to_verify[64 + 34 + 32];
                memset(c_cv_to_verify, 0x20, 64);
                memcpy(c_cv_to_verify + 64, "TLS 1.3, client CertificateVerify", 34);
                memcpy(c_cv_to_verify + 98, thash_ccert, 32);

                if (pq_verify_client_cert_and_sig(s_hs.client_cert_der, s_hs.client_cert_len,
                                                  sig_scheme, body + 4, c_sig_len,
                                                  c_cv_to_verify, sizeof(c_cv_to_verify),
                                                  conn->client_cn) != 0) {
                    return -1;
                }
                sha256_update(&transcript, msg_ptr, 4 + msg_len);
                got_client_cv = 1;
            } else if (msg_type == 0x14 && got_client_cv && !got_client_fin) {
                /* Client Finished */
                if (msg_len != 32) return -1;
                uint8_t thash_ccv[32];
                sha256_final(&transcript, thash_ccv);

                uint8_t c_fin_key[32], expected_fin[32];
                hkdf_expand_label(c_fin_key, 32, c_hs_traffic, "finished", NULL, 0);
                hmac_sha256(expected_fin, c_fin_key, 32, thash_ccv, 32);

                uint8_t diff = 0;
                for (int i = 0; i < 32; i++) diff |= expected_fin[i] ^ body[i];
                if (diff != 0) {
                    PQ_LOGE("Client Finished verify_data mismatch!");
                    return -1;
                }
                sha256_update(&transcript, msg_ptr, 4 + msg_len);
                got_client_fin = 1;
            } else {
                PQ_LOGE("Unexpected client handshake message type: 0x%02x", msg_type);
                return -1;
            }

            off += 4 + msg_len;
        }
        if (off > 0) {
            memmove(s_hs.io_buf, s_hs.io_buf + off, hs_accum - off);
            hs_accum -= off;
        }
    }

#ifdef ESP_PLATFORM
    pq_sample_heap();
    conn->hs_peak_heap_bytes = (heap_before > s_hs_min_free_heap) ? (heap_before - s_hs_min_free_heap) : 0;
#endif
    return 0;
}

int pq_mtls_write(pq_mtls_conn_t *conn, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    size_t total = 0;
    while (total < len) {
        size_t chunk = (len - total) < 1024 ? (len - total) : 1024;
        if (tls13_send_encrypted_record(conn->fd, conn->s_ap_key, conn->s_ap_iv,
                                        &conn->s_ap_seq, 0x17, p + total, chunk) != 0) {
            return -1;
        }
        total += chunk;
    }
    return (int)total;
}

int pq_mtls_read(pq_mtls_conn_t *conn, void *buf, size_t max_len) {
    if (conn->rx_plain_off < conn->rx_plain_len) {
        size_t avail = conn->rx_plain_len - conn->rx_plain_off;
        size_t copy = avail < max_len ? avail : max_len;
        memcpy(buf, conn->rx_plain + conn->rx_plain_off, copy);
        conn->rx_plain_off += copy;
        return (int)copy;
    }
    for (;;) {
        uint8_t ctype = 0;
        size_t pt_len = 0;
        int r = tls13_recv_encrypted_record(conn->fd, conn->c_ap_key, conn->c_ap_iv,
                                            &conn->c_ap_seq, &ctype,
                                            conn->rx_plain, sizeof(conn->rx_plain), &pt_len);
        if (r <= 0) return r;
        if (ctype == 0x15) {
            /* TLS Alert (e.g. close_notify = 0x01, 0x00) */
            if (pt_len >= 2 && conn->rx_plain[1] == 0x00) {
                return 0;
            }
            return -1;
        }
        if (ctype == 0x17 && pt_len > 0) {
            conn->rx_plain_len = pt_len;
            conn->rx_plain_off = 0;
            size_t copy = pt_len < max_len ? pt_len : max_len;
            memcpy(buf, conn->rx_plain, copy);
            conn->rx_plain_off = copy;
            return (int)copy;
        }
    }
}
