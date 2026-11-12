#pragma once

#include <stdint.h>
#include <stddef.h>

#define MLKEM768_EK_BYTES    1184
#define MLKEM768_CT_BYTES    1088
#define MLKEM768_SS_BYTES    32
#define MLKEM768_COINS_BYTES 32

#ifdef __cplusplus
extern "C" {
#endif

/**
 * NIST FIPS 203 ML-KEM-768 Encapsulation.
 *
 * Validates the encapsulation key `ek` (1184 bytes) per FIPS 203 Section 7.2,
 * encapsulates using randomness `coins` (32 bytes), and writes the resulting
 * ciphertext to `ct` (1088 bytes) and shared secret to `ss` (32 bytes).
 *
 * Returns 0 on success, or -1 if `ek` fails the FIPS 203 modulus check.
 */
int mlkem768_encaps(uint8_t ct[MLKEM768_CT_BYTES],
                    uint8_t ss[MLKEM768_SS_BYTES],
                    const uint8_t ek[MLKEM768_EK_BYTES],
                    const uint8_t coins[MLKEM768_COINS_BYTES]);

#ifdef __cplusplus
}
#endif
