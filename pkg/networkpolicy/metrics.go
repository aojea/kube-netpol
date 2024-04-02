package networkpolicy

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	histogramVec = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "packet_process_time",
		Help: "Time it has taken to process each packet (microseconds)",
	}, []string{"protocol", "family"})

	packetCounterVec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "packet_count",
		Help: "Number of packets",
	}, []string{"protocol", "family"})
)

var registerMetricsOnce sync.Once

// RegisterMetrics registers kube-proxy metrics.
func registerMetrics() {
	registerMetricsOnce.Do(func() {
		prometheus.Register(histogramVec)
		prometheus.Register(packetCounterVec)
	})
}
