package observability

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"time"

	"go.opentelemetry.io/otel/trace"
)

var logger = log.New(os.Stdout, "", 0)

type logEntry struct {
	Timestamp     string `json:"ts"`
	Level         string `json:"level"`
	Msg           string `json:"msg"`
	TraceID       string `json:"trace_id,omitempty"`
	SpanID        string `json:"span_id,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`
	Adapter       string `json:"adapter,omitempty"`
	Error         string `json:"error,omitempty"`
	DurationMs    float64 `json:"duration_ms,omitempty"`
}

func Log(ctx context.Context, level, msg string, fields ...func(*logEntry)) {
	entry := logEntry{
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		Level:         level,
		Msg:           msg,
		CorrelationID: CorrelationID(ctx),
	}

	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		entry.TraceID = span.SpanContext().TraceID().String()
		entry.SpanID = span.SpanContext().SpanID().String()
	}

	for _, f := range fields {
		f(&entry)
	}

	b, _ := json.Marshal(entry)
	logger.Println(string(b))
}

func Info(ctx context.Context, msg string, fields ...func(*logEntry)) {
	Log(ctx, "info", msg, fields...)
}

func Error(ctx context.Context, msg string, fields ...func(*logEntry)) {
	Log(ctx, "error", msg, fields...)
}

func WithAdapter(adapter string) func(*logEntry) {
	return func(e *logEntry) { e.Adapter = adapter }
}

func WithError(err error) func(*logEntry) {
	return func(e *logEntry) { e.Error = err.Error() }
}

func WithDuration(d time.Duration) func(*logEntry) {
	return func(e *logEntry) { e.DurationMs = float64(d.Microseconds()) / 1000.0 }
}
