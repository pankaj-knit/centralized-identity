package observability

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

type correlationKey struct{}

func CorrelationID(ctx context.Context) string {
	if id, ok := ctx.Value(correlationKey{}).(string); ok {
		return id
	}
	return ""
}

func CorrelationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cid := r.Header.Get("X-Correlation-ID")
		if cid == "" {
			cid = r.Header.Get("X-Request-ID")
		}
		if cid == "" {
			cid = uuid.New().String()
		}

		ctx := context.WithValue(r.Context(), correlationKey{}, cid)
		w.Header().Set("X-Correlation-ID", cid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func TracingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		propagator := otel.GetTextMapPropagator()
		ctx := propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))

		tracer := Tracer()
		ctx, span := tracer.Start(ctx, "HTTP "+r.Method+" "+r.URL.Path,
			trace.WithAttributes(
				attribute.String("http.method", r.Method),
				attribute.String("http.url", r.URL.Path),
				attribute.String("correlation_id", CorrelationID(ctx)),
			),
		)
		defer span.End()

		cid := CorrelationID(ctx)
		if cid == "" {
			cid = span.SpanContext().TraceID().String()
		}
		ctx = context.WithValue(ctx, correlationKey{}, cid)
		w.Header().Set("X-Correlation-ID", cid)

		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r.WithContext(ctx))

		span.SetAttributes(attribute.Int("http.status_code", sw.status))
	})
}

func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/token/exchange" {
			next.ServeHTTP(w, r)
			return
		}

		ActiveRequests.Inc()
		defer ActiveRequests.Dec()

		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r.WithContext(r.Context()))
		duration := time.Since(start).Seconds()

		status := "success"
		if sw.status >= 400 {
			status = "error"
		}

		adapter := sw.adapter
		if adapter == "" {
			adapter = "unknown"
		}

		traceID := trace.SpanFromContext(r.Context()).SpanContext().TraceID().String()

		exemplar := prometheus.Labels{"trace_id": traceID}
		RequestDuration.WithLabelValues(adapter, status).(prometheus.ExemplarObserver).ObserveWithExemplar(duration, exemplar)
		RequestTotal.WithLabelValues(adapter, status).(prometheus.ExemplarAdder).AddWithExemplar(1, exemplar)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status  int
	adapter string
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func SetAdapter(w http.ResponseWriter, adapter string) {
	if sw, ok := w.(*statusWriter); ok {
		sw.adapter = adapter
	}
}
