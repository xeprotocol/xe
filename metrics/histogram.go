package metrics

import "github.com/prometheus/client_golang/prometheus"

func newHistogram(name, help string, buckets []float64) prometheus.Histogram {
	h := prometheus.NewHistogram(prometheus.HistogramOpts{Name: name, Help: help, Buckets: buckets})
	Registry.MustRegister(h)
	return h
}
