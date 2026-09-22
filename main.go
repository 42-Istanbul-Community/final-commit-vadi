package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

const redirectURL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"

func main() {
	addr := flag.String("addr", ":22", "address to listen on")
	httpAddr := flag.String("http", ":80", "address for the HTTP redirect server")
	hostKeyPath := flag.String("hostkey", "host_ed25519", "path to the server's host key (created if missing)")
	textPath := flag.String("text", "text.txt", "file whose contents are sent to SSH clients")
	logPath := flag.String("log", "server.log", "file that connections and requests are logged to")
	flag.Parse()

	logFile, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Fatalf("log file: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(io.MultiWriter(os.Stderr, logFile))

	if err := ensureHostKey(*hostKeyPath); err != nil {
		log.Fatalf("host key: %v", err)
	}

	ssh.Handle(func(s ssh.Session) {
		log.Printf("ssh: connection from %s (user %q, command %q)", s.RemoteAddr(), s.User(), s.RawCommand())
		// Read on every connection so edits to the file show up without a restart.
		text, err := os.ReadFile(*textPath)
		if err != nil {
			log.Printf("ssh: reading %s: %v", *textPath, err)
			io.WriteString(s, "Hello, world!\n")
			return
		}
		// With a PTY the client's terminal is in raw mode, so bare \n would
		// move down without returning to column 0.
		if _, _, isPty := s.Pty(); isPty {
			text = bytes.ReplaceAll(text, []byte("\n"), []byte("\r\n"))
		}
		s.Write(text)
	})

	redirect := http.RedirectHandler(redirectURL, http.StatusFound)
	go func() {
		log.Printf("http listening on %s", *httpAddr)
		log.Fatal(http.ListenAndServe(*httpAddr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("http: %s %s %s from %s (user agent %q)", r.Method, r.Host, r.URL, r.RemoteAddr, r.UserAgent())
			redirect.ServeHTTP(w, r)
		})))
	}()

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
