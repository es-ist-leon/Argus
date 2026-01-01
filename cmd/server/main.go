package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/argus/argus/internal/server"
)

func main() {
	// Command line flags
	listenAddr := flag.String("listen", ":8443", "Agent listener address")
	apiAddr := flag.String("api", ":8080", "API server address")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file")
	tlsKey := flag.String("tls-key", "", "TLS key file")
	jwtSecret := flag.String("jwt-secret", "change-me-in-production", "JWT signing secret")
	maxAgents := flag.Int("max-agents", 1000, "Maximum number of connected agents")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	config := &server.Config{
		ListenAddr:        *listenAddr,
		APIAddr:           *apiAddr,
		TLSCertFile:       *tlsCert,
		TLSKeyFile:        *tlsKey,
		JWTSecret:         *jwtSecret,
		HeartbeatInterval: 30 * time.Second,
		SessionTimeout:    24 * time.Hour,
		MaxAgents:         *maxAgents,
		AuditLog:          true,
	}

	srv := server.NewServer(config)

	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	srv.Stop()
}
