package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	ReconcileDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "oidcapplication_reconcile_duration_seconds",
			Help:    "Time spent reconciling OIDCApplication resources",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"name", "namespace"},
	)

	ReconcileErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oidcapplication_reconcile_errors_total",
			Help: "Total reconciliation errors by error type",
		},
		[]string{"name", "namespace", "error_type"},
	)

	PolicyStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oidcapplication_status",
			Help: "Current status of OIDCApplication resources (1=Ready, 0=NotReady)",
		},
		[]string{"name", "namespace"},
	)

	AuthentikAPIRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authentik_api_requests_total",
			Help: "Total Authentik API requests by endpoint and status code",
		},
		[]string{"method", "endpoint", "status"},
	)

	AuthentikAPILatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "authentik_api_request_duration_seconds",
			Help:    "Authentik API request latency",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)

	ProviderConnected = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "authentikprovider_connected",
			Help: "Connection status of AuthentikProvider resources (1=connected, 0=disconnected)",
		},
		[]string{"name"},
	)
)

func init() {
	metrics.Registry.MustRegister(
		ReconcileDuration,
		ReconcileErrors,
		PolicyStatus,
		AuthentikAPIRequests,
		AuthentikAPILatency,
		ProviderConnected,
	)
}
