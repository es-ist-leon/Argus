# Argus - Enterprise Remote Management Tool

<p align="center">
  <img src="docs/logo.png" alt="Argus Logo" width="200">
</p>

A high-performance, secure remote management tool built with **Go** and **C++** for enterprise environments.

## Features

### Core Capabilities
- 🔒 **Secure Communication** - TLS/mTLS encryption with certificate-based authentication
- 🚀 **High Performance** - C++ native modules for system operations
- 📊 **Real-time Monitoring** - Live system metrics and process management
- 🔐 **Enterprise Authentication** - JWT-based auth with role-based access control (RBAC)
- 📝 **Audit Logging** - Comprehensive audit trail for compliance
- 🌐 **Web Dashboard** - Modern web interface for management

### Agent Capabilities
- Remote command execution
- File transfer (upload/download)
- System information collection
- Process management (list/kill)
- Service management
- Interactive shell sessions
- Network diagnostics
- Registry operations (Windows)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Argus Server                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  REST API   │  │  WebSocket  │  │ Agent Proto │             │
│  │   :8080     │  │   Server    │  │   :8443     │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│         │                │                │                     │
│  ┌──────┴────────────────┴────────────────┴──────┐             │
│  │              Command & Control Core            │             │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐       │             │
│  │  │  Auth   │  │  Agent  │  │ Command │       │             │
│  │  │ Manager │  │ Manager │  │  Queue  │       │             │
│  │  └─────────┘  └─────────┘  └─────────┘       │             │
│  └───────────────────────────────────────────────┘             │
└─────────────────────────────────────────────────────────────────┘
                              │
                    TLS/mTLS Connection
                              │
┌─────────────────────────────┼─────────────────────────────────┐
│                             │                                  │
│  ┌──────────┐    ┌──────────┴──────────┐    ┌──────────┐     │
│  │  Agent   │    │       Agent         │    │  Agent   │     │
│  │ Server 1 │    │      Server 2       │    │ Server N │     │
│  └──────────┘    └─────────────────────┘    └──────────┘     │
│        │                    │                      │          │
│  ┌─────┴─────┐       ┌─────┴─────┐         ┌─────┴─────┐    │
│  │  Native   │       │  Native   │         │  Native   │    │
│  │  Module   │       │  Module   │         │  Module   │    │
│  │   (C++)   │       │   (C++)   │         │   (C++)   │    │
│  └───────────┘       └───────────┘         └───────────┘    │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites
- Go 1.21+
- CMake 3.16+
- C++17 compatible compiler (MSVC, GCC, Clang)
- OpenSSL (optional, for TLS)

### Building

```bash
# Clone the repository
git clone https://github.com/your-org/argus.git
cd argus

# Build native modules
cd native
mkdir build && cd build
cmake ..
cmake --build . --config Release
cd ../..

# Build Go components
go mod download
go build -o bin/argus-server ./cmd/server
go build -o bin/argus-agent ./cmd/agent
```

### Running the Server

```bash
# Development mode (no TLS)
./bin/argus-server --listen :8443 --api :8080

# Production mode (with TLS)
./bin/argus-server \
  --listen :8443 \
  --api :8080 \
  --tls-cert certs/server.crt \
  --tls-key certs/server.key \
  --jwt-secret "your-secure-secret"
```

### Running the Agent

```bash
# Connect to server
./bin/argus-agent --server localhost:8443

# With TLS
./bin/argus-agent \
  --server server.example.com:8443 \
  --tls \
  --tls-ca certs/ca.crt
```

## Configuration

### Server Configuration (`configs/server.yaml`)

```yaml
server:
  listen_addr: ":8443"
  api_addr: ":8080"
  tls:
    enabled: true
    cert_file: "certs/server.crt"
    key_file: "certs/server.key"
  auth:
    jwt_secret: "${JWT_SECRET}"
    token_expiry: "24h"
  agents:
    max_connections: 10000
    heartbeat_interval: "30s"
```

### Agent Configuration (`configs/agent.yaml`)

```yaml
agent:
  server:
    addr: "server.example.com:8443"
    tls:
      enabled: true
      ca_cert: "certs/ca.crt"
  labels:
    environment: "production"
    role: "webserver"
  capabilities:
    - "execute"
    - "file_transfer"
    - "system_info"
```

## API Reference

### Authentication

```bash
# Login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme"}'

# Response
{"token":"eyJhbGciOiJIUzI1NiIs..."}
```

### Agents

```bash
# List agents
curl http://localhost:8080/api/v1/agents \
  -H "Authorization: Bearer <token>"

# Get agent details
curl http://localhost:8080/api/v1/agents/{id} \
  -H "Authorization: Bearer <token>"

# Send command
curl -X POST http://localhost:8080/api/v1/agents/{id}/commands \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "execute",
    "payload": {"command": "hostname"},
    "timeout": 30
  }'
```

### Dashboard

```bash
# Get statistics
curl http://localhost:8080/api/v1/dashboard/stats \
  -H "Authorization: Bearer <token>"
```

## Security

### Default Credentials
⚠️ **Change these immediately in production!**

- Username: `admin`
- Password: `changeme`

### Security Best Practices

1. **Enable TLS** - Always use TLS in production
2. **Use mTLS** - Enable client certificate authentication
3. **Rotate Secrets** - Regularly rotate JWT secrets and API keys
4. **Network Isolation** - Deploy server in isolated network segment
5. **Audit Logs** - Enable and monitor audit logs
6. **RBAC** - Use least-privilege principle for user roles

## Project Structure

```
argus/
├── cmd/
│   ├── server/         # Server entry point
│   └── agent/          # Agent entry point
├── internal/
│   ├── server/         # Server implementation
│   ├── agent/          # Agent implementation
│   ├── protocol/       # Wire protocol
│   ├── auth/           # Authentication
│   └── crypto/         # Cryptographic utilities
├── pkg/
│   ├── api/            # API definitions
│   ├── models/         # Data models
│   └── native/         # CGO bindings
├── native/
│   ├── sysinfo/        # C++ system info module
│   ├── procmgr/        # C++ process manager
│   └── CMakeLists.txt  # CMake build
├── web/
│   ├── static/         # Static assets
│   └── templates/      # HTML templates
├── configs/            # Configuration files
├── certs/              # TLS certificates
└── docs/               # Documentation
```

## Native Module (C++)

The native module provides high-performance system operations:

### Functions

| Function | Description |
|----------|-------------|
| `sysinfo_get_system_info` | Get comprehensive system information |
| `sysinfo_get_cpu_usage` | Get CPU usage percentage |
| `sysinfo_get_memory_info` | Get memory statistics |
| `sysinfo_get_disk_info` | Get disk usage information |
| `sysinfo_get_network_info` | Get network interface details |
| `sysinfo_get_process_list` | List running processes |
| `sysinfo_kill_process` | Terminate a process |
| `sysinfo_exec_command` | Execute a command |

### Building Native Module Only

```bash
cd native
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [gorilla/mux](https://github.com/gorilla/mux) - HTTP router
- [gorilla/websocket](https://github.com/gorilla/websocket) - WebSocket implementation
- [golang-jwt/jwt](https://github.com/golang-jwt/jwt) - JWT implementation
