package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/argoproj/argo-cd/pkg/apis/application/v1alpha1"
	repoclient "github.com/argoproj/argo-cd/util/repo/client"
	repofactory "github.com/argoproj/argo-cd/util/repo/factory"
)

type MetricsServer struct {
	handler           http.Handler
	gitRequestCounter *prometheus.CounterVec
	clientFactory     repofactory.ClientFactory
}

type GitRequestType string

const (
	GitRequestTypeLsRemote = "ls-remote"
	GitRequestTypeFetch    = "fetch"
)

// NewMetricsServer returns a new prometheus server which collects application metrics
func NewMetricsServer(clientFactory repofactory.ClientFactory) *MetricsServer {
	registry := prometheus.NewRegistry()
	registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	registry.MustRegister(prometheus.NewGoCollector())

	gitRequestCounter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "argocd_git_request_total",
			Help: "Number of git requests performed by repo server",
		},
		[]string{"repo", "request_type"},
	)
	registry.MustRegister(gitRequestCounter)

	return &MetricsServer{
		clientFactory:     clientFactory,
		handler:           promhttp.HandlerFor(registry, promhttp.HandlerOpts{}),
		gitRequestCounter: gitRequestCounter,
	}
}

func (m *MetricsServer) GetHandler() http.Handler {
	return m.handler
}

// IncGitRequest increments the git requests counter
func (m *MetricsServer) IncGitRequest(repo string, requestType GitRequestType) {
	m.gitRequestCounter.WithLabelValues(repo, string(requestType)).Inc()
}

func (m *MetricsServer) NewClient(repo *v1alpha1.Repository) (repoclient.Client, error) {
	client, err := m.clientFactory.NewClient(repo)
	if err != nil {
		return nil, err
	}
	return wrapGitClient(repo.Repo, m, client), nil
}
