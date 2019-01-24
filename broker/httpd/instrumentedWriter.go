package httpd

/* Original Instpiration comes from https://github.com/mash/go-accesslog/

 */

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type LogRecord struct {
	Time                                      time.Time
	Ip, Method, Uri, Protocol, Username, Host string
	Status                                    int
	Size                                      int64
	ElapsedTime                               time.Duration
	RequestHeader                             http.Header
	CustomRecords                             map[string]string
}

type LoggingWriter struct {
	http.ResponseWriter
	logRecord LogRecord
}

var (
	rpcDurations = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "service_http_request_processing_duration_seconds",
			Help:       "RPC latency distributions.",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"code"},
	)
	rpcDurationsHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "service_http_request_response_size",
			Help: "RPC latency distributions.",
			//Buckets: prometheus.LinearBuckets(*normMean-5**normDomain, .5**normDomain, 20),
			Buckets: prometheus.ExponentialBuckets(10.0, 1.5, 20),
		},
		[]string{"code"},
	)
)

func init() {
	// Register the summary and the histogram with Prometheus's default registry.
	prometheus.MustRegister(rpcDurations)
	prometheus.MustRegister(rpcDurationsHistogram)
}

func (r *LoggingWriter) Write(p []byte) (int, error) {
	if r.logRecord.Status == 0 {
		// The status will be StatusOK if WriteHeader has not been called yet
		r.logRecord.Status = http.StatusOK
	}
	written, err := r.ResponseWriter.Write(p)
	r.logRecord.Size += int64(written)
	return written, err
}

func (r *LoggingWriter) WriteHeader(status int) {
	r.logRecord.Status = status
	r.ResponseWriter.WriteHeader(status)
}

// w.(accesslogger.LoggingWriter).SetCustomLogRecord("X-User-Id", "3")
func (r *LoggingWriter) SetCustomLogRecord(key, value string) {
	if r.logRecord.CustomRecords == nil {
		r.logRecord.CustomRecords = map[string]string{}
	}
	r.logRecord.CustomRecords[key] = value
}

//  w.(accesslogger.LoggingWriter).SetUsername("alice")
func (r *LoggingWriter) SetUsername(username string) {
	r.logRecord.Username = username
}

// http.CloseNotifier interface
func (r *LoggingWriter) CloseNotify() <-chan bool {
	if w, ok := r.ResponseWriter.(http.CloseNotifier); ok {
		return w.CloseNotify()
	}
	return make(chan bool)
}

func (r *LoggingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := r.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("ResponseWriter doesn't support Hijacker interface")
}

// http.Flusher
func (r *LoggingWriter) Flush() {
	flusher, ok := r.ResponseWriter.(http.Flusher)
	if ok {
		flusher.Flush()
	}
}

// http.Pusher
func (r *LoggingWriter) Push(target string, opts *http.PushOptions) error {
	pusher, ok := r.ResponseWriter.(http.Pusher)
	if ok {
		return pusher.Push(target, opts)
	}
	return fmt.Errorf("ResponseWriter doesn't support Pusher interface")
}

type Logger interface {
	Log(record LogRecord)
}

type LoggingHandler struct {
	handler   http.Handler
	logger    Logger
	logBefore bool
}

func NewLoggingHandler(handler http.Handler, logger Logger) http.Handler {
	return &LoggingHandler{
		handler:   handler,
		logger:    logger,
		logBefore: false,
	}
}

func NewAroundLoggingHandler(handler http.Handler, logger Logger) http.Handler {
	return &LoggingHandler{
		handler:   handler,
		logger:    logger,
		logBefore: true,
	}
}

func NewLoggingMiddleware(logger Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := NewLoggingHandler(next, logger)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handler.ServeHTTP(w, r)
		})
	}
}

func NewAroundLoggingMiddleware(logger Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := NewAroundLoggingHandler(next, logger)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handler.ServeHTTP(w, r)
		})
	}
}

// readIp returns the real ip when behide nginx or apache
func (h *LoggingHandler) realIp(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	if ip != "127.0.0.1" {
		return ip
	}
	// Check if behind nginx or apache
	xRealIP := r.Header.Get("X-Real-Ip")
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	for _, address := range strings.Split(xForwardedFor, ",") {
		address = strings.TrimSpace(address)
		if address != "" {
			return address
		}
	}
	if xRealIP != "" {
		return xRealIP
	}
	return ip
}

func (h *LoggingHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	ip := h.realIp(r)
	username := "-"
	if r.URL.User != nil {
		if name := r.URL.User.Username(); name != "" {
			username = name
		}
	}
	startTime := time.Now()
	writer := &LoggingWriter{
		ResponseWriter: rw,
		logRecord: LogRecord{
			Time:          startTime.UTC(),
			Ip:            ip,
			Method:        r.Method,
			Uri:           r.RequestURI,
			Username:      username,
			Protocol:      r.Proto,
			Host:          r.Host,
			Status:        0,
			Size:          0,
			ElapsedTime:   time.Duration(0),
			RequestHeader: r.Header,
		},
	}
	if h.logBefore {
		writer.SetCustomLogRecord("at", "before")
		h.logger.Log(writer.logRecord)
	}
	h.handler.ServeHTTP(writer, r)
	finishTime := time.Now()
	writer.logRecord.Time = finishTime.UTC()
	writer.logRecord.ElapsedTime = finishTime.Sub(startTime)
	if h.logBefore {
		writer.SetCustomLogRecord("at", "after")
	}
	rpcDurations.WithLabelValues(fmt.Sprintf("%d", writer.logRecord.Status)).Observe(writer.logRecord.ElapsedTime.Seconds())
	rpcDurationsHistogram.WithLabelValues(fmt.Sprintf("%d", writer.logRecord.Status)).Observe(float64(writer.logRecord.Size))
	h.logger.Log(writer.logRecord)
}
