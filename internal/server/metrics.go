package server

import (
	"log"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics collects server metrics
type Metrics struct {
	mu sync.RWMutex

	// Counters
	TotalRequests      uint64
	TotalAgentConns    uint64
	TotalCommands      uint64
	TotalCommandsOK    uint64
	TotalCommandsFail  uint64
	TotalBytesReceived uint64
	TotalBytesSent     uint64

	// Gauges
	ActiveAgents     int64
	ActiveWebSockets int64
	PendingCommands  int64

	// Histograms (simplified - just tracking last N values)
	RequestLatencies []time.Duration
	CommandLatencies []time.Duration
	latencyMu        sync.Mutex
	maxLatencies     int

	// Timestamps
	StartTime time.Time
	LastReset time.Time
}

// NewMetrics creates a new metrics collector
func NewMetrics() *Metrics {
	now := time.Now()
	return &Metrics{
		RequestLatencies: make([]time.Duration, 0, 1000),
		CommandLatencies: make([]time.Duration, 0, 1000),
		maxLatencies:     1000,
		StartTime:        now,
		LastReset:        now,
	}
}

// IncrementRequests increments total request counter
func (m *Metrics) IncrementRequests() {
	atomic.AddUint64(&m.TotalRequests, 1)
}

// IncrementAgentConns increments total agent connections
func (m *Metrics) IncrementAgentConns() {
	atomic.AddUint64(&m.TotalAgentConns, 1)
}

// IncrementCommands increments command counters
func (m *Metrics) IncrementCommands(success bool) {
	atomic.AddUint64(&m.TotalCommands, 1)
	if success {
		atomic.AddUint64(&m.TotalCommandsOK, 1)
	} else {
		atomic.AddUint64(&m.TotalCommandsFail, 1)
	}
}

// AddBytesReceived adds to received bytes counter
func (m *Metrics) AddBytesReceived(n uint64) {
	atomic.AddUint64(&m.TotalBytesReceived, n)
}

// AddBytesSent adds to sent bytes counter
func (m *Metrics) AddBytesSent(n uint64) {
	atomic.AddUint64(&m.TotalBytesSent, n)
}

// SetActiveAgents sets the active agents gauge
func (m *Metrics) SetActiveAgents(n int64) {
	atomic.StoreInt64(&m.ActiveAgents, n)
}

// SetActiveWebSockets sets the active websockets gauge
func (m *Metrics) SetActiveWebSockets(n int64) {
	atomic.StoreInt64(&m.ActiveWebSockets, n)
}

// SetPendingCommands sets the pending commands gauge
func (m *Metrics) SetPendingCommands(n int64) {
	atomic.StoreInt64(&m.PendingCommands, n)
}

// RecordRequestLatency records a request latency
func (m *Metrics) RecordRequestLatency(d time.Duration) {
	m.latencyMu.Lock()
	defer m.latencyMu.Unlock()

	if len(m.RequestLatencies) >= m.maxLatencies {
		m.RequestLatencies = m.RequestLatencies[1:]
	}
	m.RequestLatencies = append(m.RequestLatencies, d)
}

// RecordCommandLatency records a command latency
func (m *Metrics) RecordCommandLatency(d time.Duration) {
	m.latencyMu.Lock()
	defer m.latencyMu.Unlock()

	if len(m.CommandLatencies) >= m.maxLatencies {
		m.CommandLatencies = m.CommandLatencies[1:]
	}
	m.CommandLatencies = append(m.CommandLatencies, d)
}

// GetStats returns current metrics as a map
func (m *Metrics) GetStats() map[string]interface{} {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	m.latencyMu.Lock()
	avgRequestLatency := m.averageLatency(m.RequestLatencies)
	avgCommandLatency := m.averageLatency(m.CommandLatencies)
	m.latencyMu.Unlock()

	return map[string]interface{}{
		// Counters
		"total_requests":       atomic.LoadUint64(&m.TotalRequests),
		"total_agent_conns":    atomic.LoadUint64(&m.TotalAgentConns),
		"total_commands":       atomic.LoadUint64(&m.TotalCommands),
		"total_commands_ok":    atomic.LoadUint64(&m.TotalCommandsOK),
		"total_commands_fail":  atomic.LoadUint64(&m.TotalCommandsFail),
		"total_bytes_received": atomic.LoadUint64(&m.TotalBytesReceived),
		"total_bytes_sent":     atomic.LoadUint64(&m.TotalBytesSent),

		// Gauges
		"active_agents":      atomic.LoadInt64(&m.ActiveAgents),
		"active_websockets":  atomic.LoadInt64(&m.ActiveWebSockets),
		"pending_commands":   atomic.LoadInt64(&m.PendingCommands),

		// Latencies
		"avg_request_latency_ms": avgRequestLatency.Milliseconds(),
		"avg_command_latency_ms": avgCommandLatency.Milliseconds(),

		// System
		"goroutines":         runtime.NumGoroutine(),
		"heap_alloc_bytes":   memStats.HeapAlloc,
		"heap_sys_bytes":     memStats.HeapSys,
		"gc_pause_total_ns":  memStats.PauseTotalNs,
		"num_gc":             memStats.NumGC,

		// Time
		"uptime_seconds":     time.Since(m.StartTime).Seconds(),
		"start_time":         m.StartTime,
	}
}

func (m *Metrics) averageLatency(latencies []time.Duration) time.Duration {
	if len(latencies) == 0 {
		return 0
	}
	var total time.Duration
	for _, l := range latencies {
		total += l
	}
	return total / time.Duration(len(latencies))
}

// PrometheusHandler returns metrics in Prometheus format
func (m *Metrics) PrometheusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		// Counters
		writeMetric(w, "argus_requests_total", "counter", "Total HTTP requests", atomic.LoadUint64(&m.TotalRequests))
		writeMetric(w, "argus_agent_connections_total", "counter", "Total agent connections", atomic.LoadUint64(&m.TotalAgentConns))
		writeMetric(w, "argus_commands_total", "counter", "Total commands executed", atomic.LoadUint64(&m.TotalCommands))
		writeMetric(w, "argus_commands_success_total", "counter", "Successful commands", atomic.LoadUint64(&m.TotalCommandsOK))
		writeMetric(w, "argus_commands_failed_total", "counter", "Failed commands", atomic.LoadUint64(&m.TotalCommandsFail))
		writeMetric(w, "argus_bytes_received_total", "counter", "Total bytes received", atomic.LoadUint64(&m.TotalBytesReceived))
		writeMetric(w, "argus_bytes_sent_total", "counter", "Total bytes sent", atomic.LoadUint64(&m.TotalBytesSent))

		// Gauges
		writeMetric(w, "argus_active_agents", "gauge", "Currently connected agents", atomic.LoadInt64(&m.ActiveAgents))
		writeMetric(w, "argus_active_websockets", "gauge", "Active WebSocket connections", atomic.LoadInt64(&m.ActiveWebSockets))
		writeMetric(w, "argus_pending_commands", "gauge", "Commands pending execution", atomic.LoadInt64(&m.PendingCommands))

		// Go runtime
		writeMetric(w, "argus_goroutines", "gauge", "Number of goroutines", runtime.NumGoroutine())
		writeMetric(w, "argus_heap_bytes", "gauge", "Heap memory in use", memStats.HeapAlloc)
		writeMetric(w, "argus_gc_pause_seconds_total", "counter", "Total GC pause time", float64(memStats.PauseTotalNs)/1e9)

		// Uptime
		writeMetric(w, "argus_uptime_seconds", "gauge", "Server uptime", time.Since(m.StartTime).Seconds())
	}
}

func writeMetric(w http.ResponseWriter, name, mtype, help string, value interface{}) {
	w.Write([]byte("# HELP " + name + " " + help + "\n"))
	w.Write([]byte("# TYPE " + name + " " + mtype + "\n"))
	switch v := value.(type) {
	case uint64:
		w.Write([]byte(name + " " + formatUint(v) + "\n"))
	case int64:
		w.Write([]byte(name + " " + formatInt(v) + "\n"))
	case int:
		w.Write([]byte(name + " " + formatInt(int64(v)) + "\n"))
	case float64:
		w.Write([]byte(name + " " + formatFloat(v) + "\n"))
	}
}

func formatUint(v uint64) string {
	return uintToStr(v)
}

func formatInt(v int64) string {
	if v < 0 {
		return "-" + uintToStr(uint64(-v))
	}
	return uintToStr(uint64(v))
}

func formatFloat(v float64) string {
	// Simple float formatting
	intPart := int64(v)
	fracPart := int64((v - float64(intPart)) * 1000000)
	if fracPart < 0 {
		fracPart = -fracPart
	}
	return formatInt(intPart) + "." + padLeft(uintToStr(uint64(fracPart)), 6, '0')
}

func uintToStr(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func padLeft(s string, length int, pad byte) string {
	if len(s) >= length {
		return s
	}
	result := make([]byte, length)
	padLen := length - len(s)
	for i := 0; i < padLen; i++ {
		result[i] = pad
	}
	copy(result[padLen:], s)
	return string(result)
}

// MetricsMiddleware wraps handlers to collect metrics
func (m *Metrics) MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		m.IncrementRequests()

		// Wrap response writer to capture status
		wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}
		next.ServeHTTP(wrapped, r)

		m.RecordRequestLatency(time.Since(start))
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// StartMetricsServer starts a separate metrics server
func StartMetricsServer(addr string, metrics *Metrics) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", metrics.PrometheusHandler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Ready"))
	})

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		log.Printf("Metrics server started on %s", addr)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("Metrics server error: %v", err)
		}
	}()

	return server
}
