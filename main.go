package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"log"
	"os"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

func main() {
	addr := flag.String("addr", ":22", "address to listen on")
	hostKeyPath := flag.String("hostkey", "host_ed25519", "path to the server's host key (created if missing)")
	flag.Parse()

	if err := ensureHostKey(*hostKeyPath); err != nil {
		log.Fatalf("host key: %v", err)
	}

	ssh.Handle(func(s ssh.Session) {
		log.Printf("connection from %s (user %q)", s.RemoteAddr(), s.User())
		io.WriteString(s, "Hello, world!\n")
	})

	log.Printf("listening on %s", *addr)
	// No auth handlers are configured, so any client may connect.
	log.Fatal(ssh.ListenAndServe(*addr, nil, ssh.HostKeyFile(*hostKeyPath)))
}

func ensureHostKey(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		return err
	}
	log.Printf("generated new host key at %s", path)
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
}
