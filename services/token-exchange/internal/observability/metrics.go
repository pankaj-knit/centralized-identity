package observability

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	RequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "identity_fabric",
		Subsystem: "token_exchange",
		Name:      "request_duration_seconds",
		Help:      "Token exchange request duration in seconds.",
		Buckets:   []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5},
	}, []string{"adapter", "status"})

	RequestTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "identity_fabric",
		Subsystem: "token_exchange",
		Name:      "requests_total",
		Help:      "Total token exchange requests.",
	}, []string{"adapter", "status"})

	AdapterDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "identity_fabric",
		Subsystem: "token_exchange",
		Name:      "adapter_duration_seconds",
		Help:      "Duration of individual adapter exchange calls.",
		Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5},
	}, []string{"adapter"})

	MintDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "identity_fabric",
		Subsystem: "token_exchange",
		Name:      "mint_duration_seconds",
		Help:      "Duration of canonical token minting.",
		Buckets:   []float64{.0005, .001, .005, .01, .025, .05},
	}, []string{})

	ActiveRequests = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "identity_fabric",
		Subsystem: "token_exchange",
		Name:      "active_requests",
		Help:      "Number of in-flight token exchange requests.",
	})

	TokenTrustLevel = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "identity_fabric",
		Subsystem: "token_exchange",
		Name:      "tokens_issued_total",
		Help:      "Tokens issued by trust level and auth method.",
	}, []string{"trust_level", "auth_method"})
)
