package application

import (
	"fmt"

	appv1 "github.com/argoproj/argo-cd/pkg/apis/application/v1alpha1"
	appclientset "github.com/argoproj/argo-cd/pkg/client/clientset/versioned"
	"github.com/argoproj/argo-cd/reposerver"
	"github.com/argoproj/argo-cd/reposerver/repository"
	"github.com/argoproj/argo-cd/server/cluster"
	apirepository "github.com/argoproj/argo-cd/server/repository"
	"github.com/argoproj/argo-cd/util"
	argoutil "github.com/argoproj/argo-cd/util/argo"
	"github.com/argoproj/argo-cd/util/diff"
	"github.com/argoproj/argo-cd/util/kube"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
)

// Server provides a Application service
type Server struct {
	ns            string
	kubeclientset kubernetes.Interface
	appclientset  appclientset.Interface
	repoClientset reposerver.Clientset
	// TODO(jessesuen): move common cluster code to shared libraries
	clusterService cluster.ClusterServiceServer
	repoService    apirepository.RepositoryServiceServer
}

// NewServer returns a new instance of the Application service
func NewServer(
	namespace string,
	kubeclientset kubernetes.Interface,
	appclientset appclientset.Interface,
	repoClientset reposerver.Clientset,
	repoService apirepository.RepositoryServiceServer,
	clusterService cluster.ClusterServiceServer) ApplicationServiceServer {

	return &Server{
		ns:             namespace,
		appclientset:   appclientset,
		kubeclientset:  kubeclientset,
		clusterService: clusterService,
		repoClientset:  repoClientset,
		repoService:    repoService,
	}
}

// List returns list of applications
func (s *Server) List(ctx context.Context, q *ApplicationQuery) (*appv1.ApplicationList, error) {
	return s.appclientset.ArgoprojV1alpha1().Applications(s.ns).List(metav1.ListOptions{})
}

// Create creates a application
func (s *Server) Create(ctx context.Context, a *appv1.Application) (*appv1.Application, error) {
	return s.appclientset.ArgoprojV1alpha1().Applications(s.ns).Create(a)
}

// Get returns a application by name
func (s *Server) Get(ctx context.Context, q *ApplicationQuery) (*appv1.Application, error) {
	return s.appclientset.ArgoprojV1alpha1().Applications(s.ns).Get(q.Name, metav1.GetOptions{})
}

// Update updates a application
func (s *Server) Update(ctx context.Context, a *appv1.Application) (*appv1.Application, error) {
	return s.appclientset.ArgoprojV1alpha1().Applications(s.ns).Update(a)
}

// Delete updates a application
func (s *Server) Delete(ctx context.Context, q *ApplicationQuery) (*ApplicationResponse, error) {
	err := s.appclientset.ArgoprojV1alpha1().Applications(s.ns).Delete(q.Name, &metav1.DeleteOptions{})
	return &ApplicationResponse{}, err
}

// ListPods returns pods in a application
func (s *Server) ListPods(ctx context.Context, q *ApplicationQuery) (*apiv1.PodList, error) {
	// TODO: filter by the app label
	return s.kubeclientset.CoreV1().Pods(s.ns).List(metav1.ListOptions{})
}

func (s *Server) Watch(q *ApplicationQuery, ws ApplicationService_WatchServer) error {
	w, err := s.appclientset.ArgoprojV1alpha1().Applications(s.ns).Watch(metav1.ListOptions{})
	if err != nil {
		return err
	}
	done := make(chan bool)
	go func() {
		for next := range w.ResultChan() {
			app := *next.Object.(*appv1.Application)
			if q.Name == "" || q.Name == app.Name {
				err = ws.Send(&appv1.ApplicationWatchEvent{
					Type:        next.Type,
					Application: app,
				})
				if err != nil {
					log.Warnf("Unable to send stream message: %v", err)
				}
			}
		}
		done <- true
	}()
	select {
	case <-ws.Context().Done():
		w.Stop()
	case <-done:
	}
	return nil
}

// Sync syncs an application to its target state
func (s *Server) Sync(ctx context.Context, syncReq *ApplicationSyncRequest) (*ApplicationSyncResult, error) {
	log.Infof("Syncing application %s", syncReq.Name)
	app, err := s.Get(ctx, &ApplicationQuery{Name: syncReq.Name})
	if err != nil {
		return nil, err
	}

	repo, err := s.repoService.Get(ctx, &apirepository.RepoQuery{Repo: app.Spec.Source.RepoURL})
	if err != nil {
		// Handle public repos here...
		// repo, err := ....
		repo = &appv1.Repository{
			Repo: app.Spec.Source.RepoURL,
			Username: "",
			Password: "",
		}
	}

	conn, repoClient, err := s.repoClientset.NewRepositoryClient()
	if err != nil {
		return nil, err
	}
	defer util.Close(conn)
	revision := syncReq.Revision
	if revision == "" {
		revision = app.Spec.Source.TargetRevision
	}

	manifestInfo, err := repoClient.GenerateManifest(ctx, &repository.ManifestRequest{
		Repo:        repo,
		Environment: app.Spec.Source.Environment,
		Path:        app.Spec.Source.Path,
		Revision:    revision,
	})
	if err != nil {
		return nil, err
	}
	server, namespace := argoutil.ResolveServerNamespace(app, manifestInfo)

	clst, err := s.clusterService.Get(ctx, &cluster.ClusterQuery{Server: server})
	if err != nil {
		return nil, err
	}
	config := clst.RESTConfig()

	targetObjs := make([]*unstructured.Unstructured, len(manifestInfo.Manifests))
	for i, manifest := range manifestInfo.Manifests {
		obj, err := appv1.UnmarshalToUnstructured(manifest)
		if err != nil {
			return nil, err
		}
		targetObjs[i] = obj
	}

	liveObjs, err := kube.GetLiveResources(config, targetObjs, namespace)
	if err != nil {
		return nil, err
	}
	diffResList, err := diff.DiffArray(targetObjs, liveObjs)
	if err != nil {
		return nil, err
	}
	var syncRes ApplicationSyncResult
	syncRes.Resources = make([]*ResourceDetails, 0)
	for i, diffRes := range diffResList.Diffs {
		resDetails := ResourceDetails{
			Name:      targetObjs[i].GetName(),
			Kind:      targetObjs[i].GetKind(),
			Namespace: namespace,
		}
		needsCreate := bool(liveObjs[i] == nil)
		if !diffRes.Modified {
			resDetails.Message = fmt.Sprintf("already synced")
		} else if syncReq.DryRun {
			if needsCreate {
				resDetails.Message = fmt.Sprintf("will create")
			} else {
				resDetails.Message = fmt.Sprintf("will update")
			}
		} else {
			_, err := kube.ApplyResource(config, targetObjs[i], namespace)
			if err != nil {
				return nil, err
			}
			if needsCreate {
				resDetails.Message = fmt.Sprintf("created")
			} else {
				resDetails.Message = fmt.Sprintf("updated")
			}
		}
		syncRes.Resources = append(syncRes.Resources, &resDetails)
	}
	syncRes.Message = "successfully synced"
	return &syncRes, nil
}
