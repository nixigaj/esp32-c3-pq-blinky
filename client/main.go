package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Minimal Linux termios raw mode helper using standard library syscall
type termios struct {
	Iflag  uint32
	Oflag  uint32
	Cflag  uint32
	Lflag  uint32
	Line   uint8
	Cc     [32]uint8
	Ispeed uint32
	Ospeed uint32
}

const (
	tcgets = 0x5401
	tcsets = 0x5402
)

func enableRawMode(fd int) (*termios, error) {
	var orig termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tcgets, uintptr(unsafe.Pointer(&orig)))
	if errno != 0 {
		return nil, errno
	}
	raw := orig
	// Disable canonical mode (line buffering) and echo so SPACE triggers immediately
	raw.Lflag &^= syscall.ICANON | syscall.ECHO | syscall.ISIG
	raw.Iflag &^= syscall.IXON | syscall.ICRNL
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tcsets, uintptr(unsafe.Pointer(&raw)))
	if errno != 0 {
		return nil, errno
	}
	return &orig, nil
}

func restoreTermMode(fd int, orig *termios) {
	if orig != nil {
		syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tcsets, uintptr(unsafe.Pointer(orig)))
	}
}

func findCertsDir(explicit string) string {
	if explicit != "" {
		return explicit
	}
	candidates := []string{"certs", ".", "../certs"}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "certs"),
			exeDir,
			filepath.Join(exeDir, "../certs"),
		)
	}
	for _, c := range candidates {
		if st, err := os.Stat(filepath.Join(c, "ca.crt")); err == nil && !st.IsDir() {
			return c
		}
	}
	return "certs"
}

func main() {
	addr := flag.String("addr", "192.168.43.10:8443", "ESP32-C3 PQ-mTLS server address (host:port)")
	certsDirFlag := flag.String("certs", "", "Path to certificates directory (ca.crt, client.crt, client.key)")
	onceBlink := flag.Bool("blink-once", false, "Send one BLINK command and exit (non-interactive test mode)")
	flag.Parse()

	certsDir := findCertsDir(*certsDirFlag)
	caPath := filepath.Join(certsDir, "ca.crt")
	certPath := filepath.Join(certsDir, "client.crt")
	keyPath := filepath.Join(certsDir, "client.key")

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		log.Fatalf("read ca cert (%s): %v", caPath, err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		log.Fatalf("parse ca cert (%s) failed", caPath)
	}

	clientCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("load client keypair (%s, %s): %v", certPath, keyPath, err)
	}

	tlsConfig := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		Certificates:     []tls.Certificate{clientCert},
		RootCAs:          caPool,
		ServerName:       "esp32c3.local",
	}

	log.Printf("connecting to %s", *addr)
	t0 := time.Now()
	conn, err := tls.Dial("tcp", *addr, tlsConfig)
	if err != nil {
		log.Fatalf("handshake failed: %v", err)
	}
	hsElapsed := time.Since(t0)
	defer conn.Close()

	state := conn.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		log.Fatalf("unexpected tls version: 0x%04x", state.Version)
	}
	if state.CurveID != tls.X25519MLKEM768 {
		log.Fatalf("unexpected curve: %s (0x%04x)", state.CurveID.String(), uint16(state.CurveID))
	}
	if state.CipherSuite != tls.TLS_CHACHA20_POLY1305_SHA256 {
		log.Fatalf("unexpected cipher: %s (0x%04x)", tls.CipherSuiteName(state.CipherSuite), state.CipherSuite)
	}

	peerCN := "unknown"
	if len(state.PeerCertificates) > 0 {
		peerCN = state.PeerCertificates[0].Subject.CommonName
	}

	log.Printf("handshake done in %v (%s, %s, peer=%s)",
		hsElapsed.Round(time.Millisecond),
		state.CurveID.String(),
		tls.CipherSuiteName(state.CipherSuite),
		peerCN,
	)

	if *onceBlink {
		log.Println("sending BLINK")
		if _, err := conn.Write([]byte("BLINK\n")); err != nil {
			log.Fatalf("write failed: %v", err)
		}
		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf("read failed: %v", err)
		}
		log.Printf("%s received", strings.TrimSpace(line))
		return
	}

	log.Println("ready (SPACE=blink, BOOT=button log, q=quit)")

	stdinFd := int(os.Stdin.Fd())
	origTerm, rawErr := enableRawMode(stdinFd)
	if rawErr == nil {
		defer restoreTermMode(stdinFd, origTerm)
	}

	doneCh := make(chan struct{})

	go func() {
		defer close(doneCh)
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			log.Printf("%s received", line)
		}
		if err := scanner.Err(); err != nil && err != io.EOF {
			log.Printf("connection error: %v", err)
		} else {
			log.Println("connection closed")
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		restoreTermMode(stdinFd, origTerm)
		conn.Close()
		os.Exit(0)
	}()

	keyCh := make(chan byte, 16)
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				keyCh <- buf[0]
			}
			if err != nil {
				close(keyCh)
				return
			}
		}
	}()

	for {
		select {
		case <-doneCh:
			return
		case b, ok := <-keyCh:
			if !ok {
				return
			}
			switch b {
			case 3, 'q', 'Q':
				log.Println("disconnecting")
				return
			case ' ':
				log.Println("sending BLINK")
				if _, err := conn.Write([]byte("BLINK\n")); err != nil {
					log.Printf("write error: %v", err)
					return
				}
			}
		}
	}
}
