package application

import (
	"github.com/argoproj/argo-cd/util/http"
)

func init() {
	forward_ApplicationService_PodLogs_0 = http.StreamForwarder
	forward_ApplicationService_WatchApplications_0 = http.StreamForwarder
	forward_ApplicationService_ListApplications_0 = http.UnaryForwarder
	forward_ApplicationService_ManagedResources_0 = http.UnaryForwarder
}
