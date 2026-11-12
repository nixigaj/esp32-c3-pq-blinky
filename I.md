# ESP32-C3 Post-Quantum mTLS (`X25519MLKEM768`) Blinky & Button Controller

A post-quantum mutual-TLS (TLS 1.3) TCP server running on an **ESP32-C3** (RISC-V, 160 MHz, 4 MB Flash) paired with a **Go CLI client** that runs on either a Linux desktop or directly on an Android phone (Termux) over a WPA3 40 MHz Wi-Fi hotspot.

## Overview

- **Key Exchange**: `X25519MLKEM768` (`0x11EC`) — hybrid post-quantum key exchange combining NIST FIPS 203 **ML-KEM-768** (1,184-byte encapsulation key, 1,088-byte ciphertext) with **X25519** ECDH.
- **Cipher Suite**: `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`) — RFC 8439 ChaCha20-Poly1305 AEAD record protection + SHA-256 HKDF key schedule.
- **Mutual Authentication (mTLS)**: ECDSA P-256 (`ecdsa_secp256r1_sha256`, `0x0403`) X.509 certificates signed by a dedicated Root CA (`certs/`). Both the ESP32-C3 server and Go client verify the peer's certificate chain and `CertificateVerify` signature.
- **Interactive Controls**:
  - Pressing `SPACE` in the CLI sends an encrypted `BLINK\n` record to the ESP32-C3, which blinks the onboard blue LED (`GPIO 8`, active-low) for 100 ms, logs the event, and replies with `BLINK_ACK\n`.
  - Pressing the physical `BOOT` button (`GPIO 9`, active-low) on the ESP32-C3 sends an encrypted `BOOT_PRESSED seq=<n>\n` record to the CLI terminal.

---

## Architecture & Implementation Details

```text
+-----------------------------------+          TLS 1.3 (TCP :8443)          +-----------------------------------+
|  Go CLI Client (client/)          | <===================================> |  ESP32-C3 Server (main/)          |
|  - Fedora x86_64 or Pixel Termux  |   KEX:    X25519MLKEM768 (0x11EC)     |  - Static IP: 192.168.43.10/24    |
|  - crypto/tls (Go 1.26)           |   Cipher: ChaCha20-Poly1305 (0x1303)  |  - Custom RFC 8446 TLS 1.3 engine |
|  - Raw termios SPACE -> "BLINK\n" |   Auth:   Mutual ECDSA P-256 X.509    |  - Custom FIPS 203 ML-KEM-768     |
+-----------------------------------+                                       +-----------------------------------+
```

### 1. Post-Quantum TLS 1.3 Handshake (`main/pq_mtls.c` & `main/mlkem768.c`)

Because ESP-IDF's built-in mbedTLS does not yet support TLS 1.3 `X25519MLKEM768` (`0x11EC`), the ESP32-C3 runs a custom RFC 8446 TLS 1.3 server engine in [`main/pq_mtls.c`](main/pq_mtls.c) backed by a scratch C implementation of NIST FIPS 203 ML-KEM-768 in [`main/mlkem768.c`](main/mlkem768.c):

1. **`ClientHello` & Hybrid Key Share**:
   - The Go client connects to TCP port `8443` and sends a TLS 1.3 `ClientHello` offering `X25519MLKEM768` (`0x11EC`) and `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`).
   - Inside the `key_share` extension for group `0x11EC`, the client sends **1,216 bytes**:
     ```text
     [ ML-KEM-768 Encapsulation Key (1,184 bytes) || X25519 Public Key (32 bytes) ]
     ```
2. **`ServerHello` & Key Encapsulation**:
   - The ESP32-C3 runs [`mlkem768_encaps()`](main/mlkem768.c) (Keccak-f[1600] SHA3/SHAKE + 256-coefficient NTT polynomial arithmetic mod `3329`) against the client's 1,184-byte encapsulation key to produce a **1,088-byte ciphertext** and a **32-byte ML-KEM shared secret**.
   - It then generates an ephemeral X25519 keypair via PSA Crypto (`psa_raw_key_agreement`) to compute a **32-byte X25519 shared secret**, and replies with a `ServerHello` carrying its **1,120-byte** `key_share`:
     ```text
     [ ML-KEM-768 Ciphertext (1,088 bytes) || Server X25519 Public Key (32 bytes) ]
     ```
3. **TLS 1.3 HKDF-SHA256 Key Schedule**:
   - Both sides concatenate the hybrid shared secret in `X25519MLKEM768` order:
     ```text
     shared_secret (64 bytes) = ML-KEM-768_ss (32 bytes) || X25519_ss (32 bytes)
     ```
   - Using RFC 8446 `HKDF-Extract` and `HKDF-Expand-Label` over the running SHA-256 handshake transcript, the server derives `client_handshake_traffic_secret` and `server_handshake_traffic_secret` (and corresponding 32-byte ChaCha20 keys + 12-byte IVs).
4. **Encrypted Server & Client mTLS Flights**:
   - All subsequent handshake messages are wrapped inside encrypted TLS 1.3 records.
   - **Server flight**: sends `EncryptedExtensions`, `CertificateRequest` (requiring `ecdsa_secp256r1_sha256`), `Certificate` (`SERVER_CERT_DER` from [`main/certs.h`](main/certs.h)), `CertificateVerify` (ECDSA P-256 signature over the transcript hash using `SERVER_KEY_DER`), and `Finished` (HMAC-SHA256 over the transcript).
   - **Client flight**: the Go client verifies the ESP32-C3's certificate against `ca.crt`, then sends its own `Certificate` (`client.crt`), `CertificateVerify`, and `Finished`.
   - The ESP32-C3 parses the client's DER certificate with mbedTLS, verifies the signature chain against `CA_CERT_DER`, verifies the client's ECDSA P-256 `CertificateVerify` signature and `Finished` MAC, and derives the final `client_application_traffic_secret_0` and `server_application_traffic_secret_0`.

### 2. How Messages Are Sent Over TCP (`TLS_CHACHA20_POLY1305_SHA256`)

Once the handshake finishes, [`pq_mtls_write()`](main/pq_mtls.c) and [`pq_mtls_read()`](main/pq_mtls.c) exchange application messages over the TCP socket using RFC 8446 TLS 1.3 record framing (`TLSCiphertext`):

```text
+-------------------+-------------------+---------------------------------------+-------------------+
| ContentType (1 B) | LegacyVer (2 B)   | Length (2 B, big-endian)              | Encrypted Payload |
|   0x17 (AppData)  |   0x03 0x03       |   len(plaintext) + 1 (type) + 16 (tag)|   + 16 B Poly1305 |
+-------------------+-------------------+---------------------------------------+-------------------+
```

1. **Inner Plaintext & Nonce Construction**:
   - Before encryption, 1 byte of `inner_content_type` (`0x17` for application data, `0x16` for handshake, `0x15` for alerts) is appended to the plaintext payload (`TLSInnerPlaintext`).
   - Each direction maintains a 64-bit sequence counter (`c_ap_seq` / `s_ap_seq`, initialized to `0`). For each record, the 96-bit (12-byte) ChaCha20-Poly1305 nonce is constructed by XORing the 12-byte traffic IV with the big-endian 64-bit sequence number in the lower 8 bytes.
   - The 5-byte TLS record header (`0x17 0x03 0x03 || length`) is passed as Additional Authenticated Data (AAD) into Poly1305.
2. **Application Wire Protocol (`main/esp-blinky-test.c` & `client/main.go`)**:
   - Application messages are newline-delimited ASCII strings inside the encrypted stream:
     - **Client -> ESP32-C3 (`BLINK\n`)**: In [`client/main.go`](client/main.go), the terminal is placed into raw mode (`ICANON | ECHO | ISIG` cleared via `ioctl` `TCSETS`) so pressing `SPACE` immediately writes `"BLINK\n"` to the `tls.Conn` without waiting for `Enter`.
     - **ESP32-C3 -> Client (`BLINK_ACK\n`)**: On the ESP32-C3, [`handle_mtls_client()`](main/esp-blinky-test.c) polls the socket with `select()` (20 ms timeout). When `"BLINK"` is decrypted, it notifies `led_blink_task` via `xTaskNotifyGive()` (which pulls `GPIO 8` low for 100 ms and high again) and writes `"BLINK_ACK\n"` back over the encrypted connection.
     - **ESP32-C3 -> Client (`BOOT_PRESSED seq=<n>\n`)**: A dedicated FreeRTOS task (`boot_button_task`) polls `GPIO 9` every 15 ms with a 30 ms debounce filter. Each press pushes an incrementing sequence number onto `s_boot_btn_queue`. Between `select()` slices, `handle_mtls_client()` drains `s_boot_btn_queue` and sends `"BOOT_PRESSED seq=<n>\n"` over the encrypted session, which a background goroutine in the Go client prints immediately.

### 3. Android Hotspot Routing & Termux Compatibility

- **Hotspot Static Subnet (`pixel-script.sh`)**: Android's hotspot `IpServer` dynamically assigns a randomized `10.x.y.0/24` subnet via DHCP and drops traffic to unconfigured subnets via policy routing (`ip rule` priority `32000: unreachable`). [`pixel-script.sh`](pixel-script.sh) (installed at `/data/adb/service.d/fixed_hotspot_subnet.sh`) attaches `192.168.43.1/24` to the hotspot interface (`ap_br_wlan2` / `wlan2`), disables `rp_filter` and `send_redirects`, and adds priority `9000` policy rules (`to 192.168.43.0/24 lookup main` and `from 192.168.43.0/24 lookup main`) plus `iptables` `FORWARD` / `tetherctrl_FORWARD` rules.
- **Termux ARM64 Binary (`client/build-android.sh`)**: Android's Bionic dynamic linker (`/system/bin/linker64`) requires Position-Independent Executables (`ET_DYN` / `e_type: 3`) and 64-byte `PT_TLS` alignment on ARM64. [`client/build-android.sh`](client/build-android.sh) builds with `CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -buildmode=pie -ldflags="-s -w"`.

---

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

---

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
