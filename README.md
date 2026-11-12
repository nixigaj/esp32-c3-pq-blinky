# ESP32-C3 Post-Quantum mTLS (`X25519MLKEM768`) Blinky & Button Controller

A post-quantum mutual-TLS (TLS 1.3) TCP server running on an **ESP32-C3** (RISC-V, 160 MHz, 4 MB Flash) paired with a **Go CLI client** that runs on either a Linux desktop or directly on an Android phone (Termux) over a WPA3 40 MHz Wi-Fi hotspot.

## Overview

- **Key Exchange**: `X25519MLKEM768` (`0x11EC`) — hybrid post-quantum key exchange combining NIST FIPS 203 **ML-KEM-768** (1184-byte encapsulation key, 1088-byte ciphertext) with **X25519** ECDH.
- **Cipher Suite**: `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`) — RFC 8439 ChaCha20-Poly1305 AEAD record protection + SHA-256 HKDF key schedule.
- **Mutual Authentication (mTLS)**: ECDSA P-256 (`ecdsa_secp256r1_sha256`, `0x0403`) X.509 certificates signed by a dedicated Root CA (`certs/`). Both server and client verify the peer's certificate chain and `CertificateVerify` signature.
- **Interactive Controls**:
  - Pressing `SPACE` in the CLI sends an encrypted `BLINK\n` record to the ESP32-C3, which blinks the onboard blue LED (`GPIO 8`, active-low) for 100 ms, logs the event, and replies with `BLINK_ACK\n`.
  - Pressing the physical `BOOT` button (`GPIO 9`, active-low) on the ESP32-C3 sends an encrypted `BOOT_PRESSED seq=<n>\n` record to the CLI terminal.

## Architecture

```text
+-----------------------------------+          TLS 1.3 (TCP :8443)          +-----------------------------------+
|  Go CLI Client (client/)          | <===================================> |  ESP32-C3 Server (main/)          |
|  - Fedora x86_64 or Pixel Termux  |   KEX:    X25519MLKEM768 (0x11EC)     |  - Static IP: 192.168.43.10/24    |
|  - crypto/tls (Go 1.26)           |   Cipher: ChaCha20-Poly1305 (0x1303)  |  - Custom RFC 8446 TLS 1.3 engine |
|  - Raw termios SPACE -> "BLINK\n" |   Auth:   Mutual ECDSA P-256 X.509    |  - Custom FIPS 203 ML-KEM-768     |
+-----------------------------------+                                       +-----------------------------------+
```

### Repository Structure

- [`main/esp-blinky-test.c`](main/esp-blinky-test.c): Wi-Fi WPA3-SAE (40 MHz) station setup with static IP `192.168.43.10`, FreeRTOS tasks for `GPIO 8` (LED) and `GPIO 9` (`BOOT` button debounce), and the TCP `:8443` server loop.
- [`main/mlkem768.c`](main/mlkem768.c) & [`main/mlkem768.h`](main/mlkem768.h): Self-contained C implementation of **NIST FIPS 203 ML-KEM-768** (`k=3, n=256, q=3329`) with SHA3-256/512, SHAKE-128/256 (Keccak-f[1600]), NTT/INTT, and deterministic/random encapsulation (`mlkem768_encaps`).
- [`main/pq_mtls.c`](main/pq_mtls.c) & [`main/pq_mtls.h`](main/pq_mtls.h): RFC 8446 TLS 1.3 server state machine (`ClientHello` -> `ServerHello` -> `EncryptedExtensions` -> `CertificateRequest` -> `Certificate` -> `CertificateVerify` -> `Finished`), HKDF-SHA256 key schedule, ChaCha20-Poly1305 record layer, and mbedTLS/PSA Crypto integration for X25519, ECDSA P-256, and X.509 verification.
- [`main/certs.h`](main/certs.h): Embedded DER bytes for the Root CA, ESP32-C3 server certificate, and server private key.
- [`client/main.go`](client/main.go): Go 1.26 CLI client enforcing TLS 1.3, `tls.X25519MLKEM768`, and `tls.TLS_CHACHA20_POLY1305_SHA256`.
- [`client/build-android.sh`](client/build-android.sh): Cross-compiles a static Position-Independent Executable (`GOOS=android GOARCH=arm64 -buildmode=pie`) for Termux on Android.
- [`pixel-script.sh`](pixel-script.sh): Magisk `service.d` startup script for the Pixel hotspot that attaches `192.168.43.1/24` to the tether interface (`ap_br_wlan2` / `wlan2`) and configures policy routing (`table main`) + `iptables` forwarding so both the phone and tethered hosts can reach `192.168.43.10`.

## Performance & ESP32-C3 Memory Metrics

Measured on an ESP32-C3 over the Pixel WPA3 hotspot (`192.168.43.10:8443`):

| Metric | Measured Value | Notes |
| :--- | :--- | :--- |
| **Client-side handshake latency** | **793 ms** (Pixel) / **819 ms** (Laptop) | From TCP `SYN` until `tls.Dial` completes (`ServerFinished` verified + `ClientFinished` sent) |
| **ESP32-C3 full handshake time** | **1,500 – 1,541 ms** | Includes ML-KEM-768 encapsulation, X25519 ECDH, ECDSA P-256 signing, and verifying the client's X.509 cert + `CertificateVerify` |
| **Static `.bss` footprint** | **7,140 B (~7.0 KB)** | `pq_mtls_conn_t` (`1,308 B`) + static handshake buffer `s_hs` (`5,832 B` for ML-KEM keys/ciphertext, TLS record buffer, and client cert DER) |
| **Peak task stack usage** | **5,932 B (~5.8 KB)** | Out of `12,288 B` allocated to `pq_mtls_srv` (covers ML-KEM-768 NTT polynomials, Keccak state, and mbedTLS frames) |
| **Peak dynamic heap usage** | **6,644 – 8,112 B (~6.5 – 7.9 KB)** | Transient mbedTLS/PSA allocations during X.509 parsing and ECDSA P-256 verification (freed before handshake returns) |
| **Total peak handshake RAM** | **19.7 – 21.2 KB** | Sum of static `.bss` + peak stack + peak dynamic heap; **~191.2 KB** of system heap remains free at peak load |

## Building & Running

### 1. ESP32-C3 Firmware
```bash
source /home/nixigaj/dev/sdk/esp/export.sh
idf.py -p /dev/ttyACM0 build flash monitor
```

### 2. Linux Host Client
```bash
cd client
go build -o client .
./client
```

### 3. Android (Termux) Client
```bash
cd client
./build-android.sh
# Copy client-android-arm64 and certs/{ca.crt,client.crt,client.key} to Termux, then:
./client-android-arm64
```
