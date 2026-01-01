package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/argus/argus/internal/agent"
)

func main() {
	// Command line flags
	serverAddr := flag.String("server", "localhost:8443", "Server address")
	agentID := flag.String("id", "", "Agent ID (auto-generated if empty)")
	tlsEnabled := flag.Bool("tls", false, "Enable TLS")
	tlsCACert := flag.String("tls-ca", "", "TLS CA certificate file")
	tlsCert := flag.String("tls-cert", "", "TLS client certificate file")
	tlsKey := flag.String("tls-key", "", "TLS client key file")
	tlsInsecure := flag.Bool("tls-insecure", false, "Skip TLS certificate verification")
	heartbeat := flag.Duration("heartbeat", 30*time.Second, "Heartbeat interval")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	config := &agent.Config{
		AgentID:           *agentID,
		ServerAddr:        *serverAddr,
		TLSEnabled:        *tlsEnabled,
		TLSCACert:         *tlsCACert,
		TLSCert:           *tlsCert,
		TLSKey:            *tlsKey,
		TLSInsecure:       *tlsInsecure,
		HeartbeatInterval: *heartbeat,
		ReconnectInterval: 10 * time.Second,
		Labels: map[string]string{
			"environment": "production",
		},
		Capabilities: []string{
			"execute",
			"file_transfer",
			"system_info",
			"process_list",
			"process_kill",
			"shell_session",
		},
	}

	agt := agent.NewAgent(config)

	// Load native module if available
	// native := loadNativeModule()
	// if native != nil {
	//     agt.SetNativeModule(native)
	// }

	if err := agt.Start(); err != nil {
		log.Fatalf("Failed to start agent: %v", err)
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	agt.Stop()
}
