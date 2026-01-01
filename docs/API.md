# Argus RMT - API Documentation

## Overview

The Argus Remote Management Tool provides a comprehensive REST API for managing remote agents, executing commands, transferring files, and monitoring systems.

**Base URL:** `https://your-server:8080/api/v1`

**Authentication:** All API endpoints (except `/auth/login` and `/health`) require a Bearer token in the Authorization header:
```
Authorization: Bearer <your-jwt-token>
```

---

## Authentication

### Login

```http
POST /auth/login
```

**Request Body:**
```json
{
  "username": "admin",
  "password": "your-password",
  "mfa_code": "123456"  // Optional, if MFA is enabled
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_at": "2024-01-02T12:00:00Z",
  "user": {
    "id": "uuid",
    "username": "admin",
    "email": "admin@example.com",
    "role": "admin",
    "permissions": ["*"]
  }
}
```

### Refresh Token

```http
POST /auth/refresh
```

**Request Body:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

### Logout

```http
POST /auth/logout
```

---

## Agents

### List Agents

```http
GET /agents
```

**Query Parameters:**
- `status` - Filter by status (online, offline, maintenance)
- `os` - Filter by operating system
- `search` - Search in hostname, IP, labels
- `page` - Page number (default: 1)
- `page_size` - Results per page (default: 50, max: 100)
- `sort_by` - Sort field (hostname, last_seen, status)
- `sort_order` - Sort direction (asc, desc)

**Response:**
```json
{
  "agents": [
    {
      "id": "uuid",
      "hostname": "server-01",
      "ip_address": "192.168.1.10",
      "os": "linux",
      "arch": "amd64",
      "version": "1.0.0",
      "status": "online",
      "labels": {
        "environment": "production",
        "role": "webserver"
      },
      "capabilities": ["execute", "file_transfer", "shell_session"],
      "last_seen": "2024-01-01T12:00:00Z",
      "registered_at": "2023-12-01T00:00:00Z"
    }
  ],
  "total_count": 42,
  "page": 1,
  "page_size": 50
}
```

### Get Agent

```http
GET /agents/{agent_id}
```

### Delete Agent

```http
DELETE /agents/{agent_id}
```

### Update Agent Labels

```http
PATCH /agents/{agent_id}/labels
```

**Request Body:**
```json
{
  "labels": {
    "environment": "staging",
    "team": "platform"
  }
}
```

---

## Commands

### Execute Command

```http
POST /agents/{agent_id}/commands
```

**Request Body:**
```json
{
  "type": "execute",
  "payload": {
    "command": "ls",
    "args": ["-la", "/var/log"]
  },
  "timeout": 30
}
```

**Command Types:**
- `execute` - Execute shell command
- `system_info` - Get system information
- `process_list` - List running processes
- `process_kill` - Kill a process
- `service_manage` - Manage system services
- `file_transfer` - File operations
- `shell_session` - Interactive shell
- `network_info` - Network information
- `restart` - Restart agent
- `shutdown` - Shutdown agent

**Response:**
```json
{
  "command_id": "uuid",
  "status": "queued",
  "message": "Command queued for execution"
}
```

### Get Command Result

```http
GET /agents/{agent_id}/commands/{command_id}
```

**Response:**
```json
{
  "command_id": "uuid",
  "agent_id": "uuid",
  "type": "execute",
  "status": "completed",
  "success": true,
  "exit_code": 0,
  "output": "total 32\ndrwxr-xr-x...",
  "started_at": "2024-01-01T12:00:00Z",
  "completed_at": "2024-01-01T12:00:01Z",
  "duration": "1.234s"
}
```

### Batch Command

```http
POST /commands/batch
```

**Request Body:**
```json
{
  "agent_ids": ["uuid1", "uuid2", "uuid3"],
  "type": "execute",
  "payload": {
    "command": "uptime"
  },
  "timeout": 30
}
```

---

## File Transfer

### List Directory

```http
POST /agents/{agent_id}/files/list
```

**Request Body:**
```json
{
  "path": "/var/log"
}
```

**Response:**
```json
{
  "path": "/var/log",
  "files": [
    {
      "name": "syslog",
      "path": "/var/log/syslog",
      "size": 1048576,
      "is_dir": false,
      "mode": "-rw-r--r--",
      "modified_at": "2024-01-01T12:00:00Z"
    }
  ]
}
```

### Upload File

```http
POST /agents/{agent_id}/files/upload
```

**Request Body:**
```json
{
  "remote_path": "/tmp/config.json",
  "content": "base64-encoded-content",
  "checksum": "sha256-hash"
}
```

### Download File

```http
POST /agents/{agent_id}/files/download
```

**Request Body:**
```json
{
  "remote_path": "/var/log/syslog"
}
```

### Delete File

```http
DELETE /agents/{agent_id}/files
```

**Request Body:**
```json
{
  "path": "/tmp/old-file.txt"
}
```

---

## Process Management

### List Processes

```http
GET /agents/{agent_id}/processes
```

**Response:**
```json
{
  "processes": [
    {
      "pid": 1234,
      "ppid": 1,
      "name": "nginx",
      "exe": "/usr/sbin/nginx",
      "cmdline": "nginx: master process",
      "user": "root",
      "status": "running",
      "cpu_percent": 0.5,
      "mem_percent": 2.3,
      "mem_rss": 12345678,
      "create_time": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### Kill Process

```http
POST /agents/{agent_id}/processes/{pid}/kill
```

---

## Service Management

### List Services

```http
GET /agents/{agent_id}/services
```

### Get Service Status

```http
GET /agents/{agent_id}/services/{service_name}
```

### Control Service

```http
POST /agents/{agent_id}/services/{service_name}/{action}
```

**Actions:** `start`, `stop`, `restart`, `enable`, `disable`

---

## Agent Groups

### List Groups

```http
GET /groups
```

### Create Group

```http
POST /groups
```

**Request Body:**
```json
{
  "name": "Production Servers",
  "description": "All production servers",
  "selector": {
    "environment": "production"
  }
}
```

### Get Group

```http
GET /groups/{group_id}
```

### Update Group

```http
PUT /groups/{group_id}
```

### Delete Group

```http
DELETE /groups/{group_id}
```

### Get Group Agents

```http
GET /groups/{group_id}/agents
```

### Execute Command on Group

```http
POST /groups/{group_id}/commands
```

---

## Scheduled Tasks

### List Tasks

```http
GET /tasks
```

### Create Task

```http
POST /tasks
```

**Request Body:**
```json
{
  "name": "Daily Backup Check",
  "description": "Check backup status daily",
  "schedule": {
    "type": "daily",
    "times": ["02:00"]
  },
  "command": {
    "type": "execute",
    "payload": {
      "command": "backup-check.sh"
    },
    "timeout": 300
  },
  "target_group": "production-servers",
  "enabled": true
}
```

**Schedule Types:**
- `once` - Run once at specified time
- `interval` - Run at fixed intervals (e.g., "30m", "4h")
- `daily` - Run daily at specified times
- `weekly` - Run on specified days at specified times
- `cron` - Standard cron expression

### Get Task

```http
GET /tasks/{task_id}
```

### Update Task

```http
PUT /tasks/{task_id}
```

### Delete Task

```http
DELETE /tasks/{task_id}
```

### Enable/Disable Task

```http
POST /tasks/{task_id}/enable
POST /tasks/{task_id}/disable
```

---

## Users

### List Users

```http
GET /users
```

### Create User

```http
POST /users
```

**Request Body:**
```json
{
  "username": "operator1",
  "email": "operator1@example.com",
  "password": "secure-password",
  "role": "operator"
}
```

**Roles:**
- `admin` - Full access
- `operator` - Read/write access to agents and commands
- `viewer` - Read-only access
- `auditor` - Access to audit logs only

### Get User

```http
GET /users/{user_id}
```

### Update User

```http
PUT /users/{user_id}
```

### Delete User

```http
DELETE /users/{user_id}
```

### Change Password

```http
POST /users/{user_id}/password
```

**Request Body:**
```json
{
  "current_password": "old-password",
  "new_password": "new-password"
}
```

---

## Dashboard

### Get Statistics

```http
GET /dashboard/stats
```

**Response:**
```json
{
  "total_agents": 42,
  "online_agents": 40,
  "offline_agents": 2,
  "pending_commands": 5,
  "total_commands": 12345,
  "success_rate": 99.5,
  "agents_by_os": {
    "linux": 35,
    "windows": 7
  },
  "agents_by_status": {
    "online": 40,
    "offline": 2
  },
  "recent_activity": [
    {
      "id": "uuid",
      "type": "agent_connected",
      "message": "Agent server-01 connected",
      "timestamp": "2024-01-01T12:00:00Z",
      "success": true
    }
  ]
}
```

---

## Audit Log

### List Audit Logs

```http
GET /audit
```

**Query Parameters:**
- `user_id` - Filter by user
- `action` - Filter by action
- `resource` - Filter by resource
- `from` - Start date (ISO 8601)
- `to` - End date (ISO 8601)
- `page` - Page number
- `page_size` - Results per page

**Response:**
```json
{
  "logs": [
    {
      "id": "uuid",
      "timestamp": "2024-01-01T12:00:00Z",
      "user_id": "uuid",
      "username": "admin",
      "action": "command.execute",
      "resource": "agent/uuid",
      "details": {
        "command_type": "execute",
        "command": "ls -la"
      },
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0...",
      "success": true
    }
  ],
  "total_count": 1000,
  "page": 1,
  "page_size": 50
}
```

---

## Alerts

### List Alert Rules

```http
GET /alerts/rules
```

### Create Alert Rule

```http
POST /alerts/rules
```

**Request Body:**
```json
{
  "name": "High CPU Alert",
  "type": "high_cpu",
  "severity": "warning",
  "threshold": 90.0,
  "duration": "5m",
  "channels": ["slack", "email"],
  "enabled": true
}
```

### Get Active Alerts

```http
GET /alerts/active
```

### Get Alert History

```http
GET /alerts/history
```

### Acknowledge Alert

```http
POST /alerts/{alert_id}/acknowledge
```

---

## WebSocket API

### Real-time Updates

```
ws://your-server:8080/api/v1/ws?token=<jwt-token>
```

**Message Types (Server → Client):**
```json
// Agent status update
{
  "type": "agent_status",
  "data": {
    "agent_id": "uuid",
    "status": "online"
  }
}

// Command result
{
  "type": "command_result",
  "data": {
    "command_id": "uuid",
    "agent_id": "uuid",
    "success": true,
    "output": "..."
  }
}

// Alert notification
{
  "type": "alert",
  "data": {
    "id": "uuid",
    "severity": "warning",
    "message": "High CPU on server-01"
  }
}
```

---

## Health Check

```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "agent_count": 42,
  "api_version": "v1",
  "server_time": "2024-01-01T12:00:00Z",
  "uptime": "72h30m15s"
}
```

---

## Error Responses

All errors follow this format:

```json
{
  "code": "VALIDATION_FAILED",
  "message": "Validation failed",
  "details": "Additional error details",
  "request_id": "uuid",
  "timestamp": 1704110400,
  "validation": [
    {
      "field": "username",
      "message": "username is required",
      "tag": "required"
    }
  ]
}
```

**Error Codes:**
- `INVALID_REQUEST` - Malformed request (400)
- `UNAUTHORIZED` - Authentication required (401)
- `FORBIDDEN` - Permission denied (403)
- `NOT_FOUND` - Resource not found (404)
- `CONFLICT` - Resource conflict (409)
- `RATE_LIMITED` - Too many requests (429)
- `INTERNAL_ERROR` - Server error (500)
- `SERVICE_UNAVAILABLE` - Service unavailable (503)
- `VALIDATION_FAILED` - Input validation failed (400)
- `AGENT_OFFLINE` - Target agent is offline (404)
- `TIMEOUT` - Operation timed out (504)
- `COMMAND_FAILED` - Command execution failed (500)

---

## Rate Limiting

API requests are rate limited to prevent abuse:

- **Default:** 100 requests/second per IP
- **Burst:** 200 requests

Rate limit headers are included in all responses:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1704110400
```

---

## Versioning

The API is versioned through the URL path (`/api/v1`). Breaking changes will result in a new version. Non-breaking changes (new fields, new endpoints) may be added without version change.
