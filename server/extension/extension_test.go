package extension_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/v2/server/extension"
	"github.com/argoproj/argo-cd/v2/server/extension/mocks"
	"github.com/argoproj/argo-cd/v2/server/rbacpolicy"
	"github.com/argoproj/argo-cd/v2/util/settings"
)

func TestValidateHeaders(t *testing.T) {
	t.Run("will build RequestResources successfully", func(t *testing.T) {
		// given
		r, err := http.NewRequest("Get", "http://null", nil)
		if err != nil {
			t.Fatalf("error initializing request: %s", err)
		}
		r.Header.Add(extension.HeaderArgoCDApplicationName, "namespace:app-name")
		r.Header.Add(extension.HeaderArgoCDProjectName, "project-name")
		r.Header.Add(extension.HeaderArgoCDResourceGVKName, "apps/v1:Pod:some-pod, argoproj.io/v1alpha1:Application:app-name, v1:Service:some-svc")

		// when
		rr, err := extension.ValidateHeaders(r)

		// then
		require.NoError(t, err)
		assert.NotNil(t, rr)
		assert.Equal(t, "namespace", rr.ApplicationNamespace)
		assert.Equal(t, "app-name", rr.ApplicationName)
		assert.Equal(t, "project-name", rr.ProjectName)
		require.Len(t, rr.Resources, 3)
		assert.Equal(t, "apps", rr.Resources[0].Gvk.Group)
		assert.Equal(t, "v1", rr.Resources[0].Gvk.Version)
		assert.Equal(t, "Pod", rr.Resources[0].Gvk.Kind)
		assert.Equal(t, "some-pod", rr.Resources[0].Name)
		assert.Equal(t, "argoproj.io", rr.Resources[1].Gvk.Group)
		assert.Equal(t, "v1alpha1", rr.Resources[1].Gvk.Version)
		assert.Equal(t, "Application", rr.Resources[1].Gvk.Kind)
		assert.Equal(t, "app-name", rr.Resources[1].Name)
		assert.Equal(t, "", rr.Resources[2].Gvk.Group)
		assert.Equal(t, "v1", rr.Resources[2].Gvk.Version)
		assert.Equal(t, "Service", rr.Resources[2].Gvk.Kind)
		assert.Equal(t, "some-svc", rr.Resources[2].Name)
	})
	t.Run("will return error if application is malformatted", func(t *testing.T) {
		// given
		r, err := http.NewRequest("Get", "http://null", nil)
		if err != nil {
			t.Fatalf("error initializing request: %s", err)
		}
		r.Header.Add(extension.HeaderArgoCDApplicationName, "no-namespace")

		// when
		rr, err := extension.ValidateHeaders(r)

		// then
		assert.Error(t, err)
		assert.Nil(t, rr)
	})
	t.Run("will return error if gvk header is malformatted", func(t *testing.T) {
		// given
		r, err := http.NewRequest("Get", "http://null", nil)
		if err != nil {
			t.Fatalf("error initializing request: %s", err)
		}
		r.Header.Add(extension.HeaderArgoCDApplicationName, "namespace:app-name")
		r.Header.Add(extension.HeaderArgoCDProjectName, "project-name")
		r.Header.Add(extension.HeaderArgoCDResourceGVKName, "no-gvk-info")

		// when
		rr, err := extension.ValidateHeaders(r)

		// then
		assert.Error(t, err)
		assert.Nil(t, rr)
	})
	t.Run("will return error if application header is missing", func(t *testing.T) {
		// given
		r, err := http.NewRequest("Get", "http://null", nil)
		if err != nil {
			t.Fatalf("error initializing request: %s", err)
		}
		r.Header.Add(extension.HeaderArgoCDProjectName, "project-name")
		r.Header.Add(extension.HeaderArgoCDResourceGVKName, "apps/v1:Pod:some-pod")

		// when
		rr, err := extension.ValidateHeaders(r)

		// then
		assert.Error(t, err)
		assert.Nil(t, rr)
	})
	t.Run("will return error if project header is missing", func(t *testing.T) {
		// given
		r, err := http.NewRequest("Get", "http://null", nil)
		if err != nil {
			t.Fatalf("error initializing request: %s", err)
		}
		r.Header.Add(extension.HeaderArgoCDApplicationName, "namespace:app-name")
		r.Header.Add(extension.HeaderArgoCDResourceGVKName, "apps/v1:Pod:some-pod")

		// when
		rr, err := extension.ValidateHeaders(r)

		// then
		assert.Error(t, err)
		assert.Nil(t, rr)
	})
}

func TestRegisterHandlers(t *testing.T) {
	type fixture struct {
		settingsGetterMock *mocks.SettingsGetter
		manager            *extension.Manager
	}

	setup := func() *fixture {
		settMock := &mocks.SettingsGetter{}

		logger, _ := test.NewNullLogger()
		logEntry := logger.WithContext(context.Background())
		m := extension.NewManager(logEntry, settMock, nil, nil)

		return &fixture{
			settingsGetterMock: settMock,
			manager:            m,
		}
	}
	t.Run("will register handlers successfully", func(t *testing.T) {
		// given
		t.Parallel()
		f := setup()
		router := mux.NewRouter()
		settings := &settings.ArgoCDSettings{
			ExtensionConfig: getExtensionConfigString(),
		}
		f.settingsGetterMock.On("Get", mock.Anything).Return(settings, nil)
		expectedRegexRoutes := []string{
			"^/extensions/",
			"^/extensions/external-backend/",
			"^/extensions/some-backend/",
			"^/extensions/$"}

		// when
		err := f.manager.RegisterHandlers(router)

		// then
		require.NoError(t, err)
		walkFn := func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
			pathRegex, err := route.GetPathRegexp()
			require.NoError(t, err)
			assert.Contains(t, expectedRegexRoutes, pathRegex)
			return nil
		}
		err = router.Walk(walkFn)
		assert.NoError(t, err)
	})
	t.Run("will return error if extension config is invalid", func(t *testing.T) {
		// given
		t.Parallel()
		type testCase struct {
			name       string
			configYaml string
		}
		cases := []testCase{
			{
				name:       "no config",
				configYaml: "",
			},
			{
				name:       "no name",
				configYaml: getExtensionConfigNoName(),
			},
			{
				name:       "no URL",
				configYaml: getExtensionConfigNoURL(),
			},
			{
				name:       "invalid name",
				configYaml: getExtensionConfigInvalidName(),
			},
		}

		// when
		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				// given
				t.Parallel()
				f := setup()
				router := mux.NewRouter()
				settings := &settings.ArgoCDSettings{
					ExtensionConfig: tc.configYaml,
				}
				f.settingsGetterMock.On("Get", mock.Anything).Return(settings, nil)

				// when
				err := f.manager.RegisterHandlers(router)

				// then
				assert.Error(t, err)
			})
		}
	})
}

func TestExtensionsHandler(t *testing.T) {
	type fixture struct {
		router             *mux.Router
		appGetterMock      *mocks.ApplicationGetter
		settingsGetterMock *mocks.SettingsGetter
		rbacMock           *mocks.RbacEnforcer
		manager            *extension.Manager
	}

	setup := func() *fixture {
		appMock := &mocks.ApplicationGetter{}
		settMock := &mocks.SettingsGetter{}
		rbacMock := &mocks.RbacEnforcer{}

		logger, _ := test.NewNullLogger()
		logEntry := logger.WithContext(context.Background())
		m := extension.NewManager(logEntry, settMock, appMock, rbacMock)

		router := mux.NewRouter()

		return &fixture{
			router:             router,
			appGetterMock:      appMock,
			settingsGetterMock: settMock,
			rbacMock:           rbacMock,
			manager:            m,
		}
	}

	getApp := func(destName, destServer string) *v1alpha1.Application {
		return &v1alpha1.Application{
			TypeMeta:   v1.TypeMeta{},
			ObjectMeta: v1.ObjectMeta{},
			Spec: v1alpha1.ApplicationSpec{
				Destination: v1alpha1.ApplicationDestination{
					Name:   destName,
					Server: destServer,
				},
			},
			Status: v1alpha1.ApplicationStatus{
				Resources: []v1alpha1.ResourceStatus{
					{
						Group:     "apps",
						Version:   "v1",
						Kind:      "Pod",
						Namespace: "default",
						Name:      "some-pod",
					},
				},
			},
		}
	}

	withRbac := func(f *fixture, allowApp, allowExt bool) {
		var appAccessError error
		var extAccessError error
		if !allowApp {
			appAccessError = errors.New("no app permission")
		}
		if !allowExt {
			extAccessError = errors.New("no extension permission")
		}
		f.rbacMock.On("EnforceErr", mock.Anything, rbacpolicy.ResourceApplications, rbacpolicy.ActionGet, mock.Anything).Return(appAccessError)
		f.rbacMock.On("EnforceErr", mock.Anything, rbacpolicy.ResourceExtensions, rbacpolicy.ActionInvoke, mock.Anything).Return(extAccessError)
	}

	withExtensionConfig := func(configYaml string, f *fixture) {
		settings := &settings.ArgoCDSettings{
			ExtensionConfig: configYaml,
		}
		f.settingsGetterMock.On("Get", mock.Anything).Return(settings, nil)
	}

	startTestServer := func(t *testing.T, f *fixture) *httptest.Server {
		err := f.manager.RegisterHandlers(f.router)
		if err != nil {
			t.Fatalf("error starting test server: %s", err)
		}
		return httptest.NewServer(f.router)
	}

	startBackendTestSrv := func(response string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, response)
		}))

	}
	newExtensionRequest := func(t *testing.T, method, url string) *http.Request {
		t.Helper()
		r, err := http.NewRequest(method, url, nil)
		if err != nil {
			t.Fatalf("error initializing request: %s", err)
		}
		r.Header.Add(extension.HeaderArgoCDApplicationName, "namespace:app-name")
		r.Header.Add(extension.HeaderArgoCDProjectName, "project-name")
		r.Header.Add(extension.HeaderArgoCDResourceGVKName, "apps/v1:Pod:some-pod")
		return r
	}

	t.Run("proxy will return 404 if no extension endpoint is registered", func(t *testing.T) {
		// given
		t.Parallel()
		f := setup()
		withExtensionConfig(getExtensionConfigString(), f)
		ts := startTestServer(t, f)
		defer ts.Close()
		nonRegisteredEndpoint := "non-registered"

		// when
		resp, err := http.Get(fmt.Sprintf("%s/extensions/%s/", ts.URL, nonRegisteredEndpoint))

		// then
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
	t.Run("will call extension backend successfully", func(t *testing.T) {
		// given
		t.Parallel()
		f := setup()
		backendResponse := "some data"
		backendEndpoint := "some-backend"
		backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, backendResponse)
		}))
		defer backendSrv.Close()
		withRbac(f, true, true)
		withExtensionConfig(getExtensionConfig(backendEndpoint, backendSrv.URL), f)
		ts := startTestServer(t, f)
		defer ts.Close()
		r := newExtensionRequest(t, "Get", fmt.Sprintf("%s/extensions/%s/", ts.URL, backendEndpoint))
		f.appGetterMock.On("Get", mock.Anything, mock.Anything).Return(getApp("", ""), nil)

		// when
		resp, err := http.DefaultClient.Do(r)

		// then
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		actual := strings.TrimSuffix(string(body), "\n")
		assert.Equal(t, backendResponse, actual)
	})
	t.Run("will route requests with 2 backends for the same extension successfully", func(t *testing.T) {
		// given
		t.Parallel()
		f := setup()
		extName := "some-extension"

		response1 := "response backend 1"
		cluster1 := "cluster1"
		beSrv1 := startBackendTestSrv(response1)
		defer beSrv1.Close()

		response2 := "response backend 2"
		cluster2 := "cluster2"
		beSrv2 := startBackendTestSrv(response2)
		defer beSrv2.Close()

		f.appGetterMock.On("Get", "ns1", "app1").Return(getApp(cluster1, beSrv1.URL), nil)
		f.appGetterMock.On("Get", "ns2", "app2").Return(getApp("", beSrv2.URL), nil)

		withRbac(f, true, true)
		withExtensionConfig(getExtensionConfigWith2Backends(extName, beSrv1.URL, cluster1, beSrv2.URL, cluster2), f)
		ts := startTestServer(t, f)
		defer ts.Close()

		url := fmt.Sprintf("%s/extensions/%s/", ts.URL, extName)
		req := newExtensionRequest(t, http.MethodGet, url)
		req.Header.Del(extension.HeaderArgoCDApplicationName)

		req1 := req.Clone(context.Background())
		req1.Header.Add(extension.HeaderArgoCDApplicationName, "ns1:app1")
		req2 := req.Clone(context.Background())
		req2.Header.Add(extension.HeaderArgoCDApplicationName, "ns2:app2")

		// when
		resp1, err := http.DefaultClient.Do(req1)
		require.NoError(t, err)
		resp2, err := http.DefaultClient.Do(req2)
		require.NoError(t, err)

		// then
		require.NotNil(t, resp1)
		assert.Equal(t, http.StatusOK, resp1.StatusCode)
		body, err := io.ReadAll(resp1.Body)
		require.NoError(t, err)
		actual := strings.TrimSuffix(string(body), "\n")
		assert.Equal(t, response1, actual)

		require.NotNil(t, resp2)
		assert.Equal(t, http.StatusOK, resp2.StatusCode)
		body, err = io.ReadAll(resp2.Body)
		require.NoError(t, err)
		actual = strings.TrimSuffix(string(body), "\n")
		assert.Equal(t, response2, actual)
	})
	t.Run("will return 401 if sub has no access to get application", func(t *testing.T) {
		// given
		t.Parallel()
		f := setup()
		allowApp := false
		allowExtension := true
		extName := "some-extension"
		withRbac(f, allowApp, allowExtension)
		withExtensionConfig(getExtensionConfig(extName, "http://fake"), f)
		ts := startTestServer(t, f)
		defer ts.Close()
		r := newExtensionRequest(t, "Get", fmt.Sprintf("%s/extensions/%s/", ts.URL, extName))
		f.appGetterMock.On("Get", mock.Anything, mock.Anything).Return(getApp("", ""), nil)

		// when
		resp, err := http.DefaultClient.Do(r)

		// then
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		actual := strings.TrimSuffix(string(body), "\n")
		assert.Contains(t, actual, "no app permission")
	})
	t.Run("will return 401 if sub has no access to invoke extension", func(t *testing.T) {
		// given
		t.Parallel()
		f := setup()
		allowApp := true
		allowExtension := false
		extName := "some-extension"
		withRbac(f, allowApp, allowExtension)
		withExtensionConfig(getExtensionConfig(extName, "http://fake"), f)
		ts := startTestServer(t, f)
		defer ts.Close()
		r := newExtensionRequest(t, "Get", fmt.Sprintf("%s/extensions/%s/", ts.URL, extName))
		f.appGetterMock.On("Get", mock.Anything, mock.Anything).Return(getApp("", ""), nil)

		// when
		resp, err := http.DefaultClient.Do(r)

		// then
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		actual := strings.TrimSuffix(string(body), "\n")
		assert.Contains(t, actual, "no extension permission")
	})
	t.Run("will return 401 if requested resource does not belong to app", func(t *testing.T) {
		// given
		t.Parallel()
		f := setup()
		allowApp := true
		allowExtension := true
		extName := "some-extension"
		withRbac(f, allowApp, allowExtension)
		withExtensionConfig(getExtensionConfig(extName, "http://fake"), f)
		ts := startTestServer(t, f)
		defer ts.Close()
		r := newExtensionRequest(t, "Get", fmt.Sprintf("%s/extensions/%s/", ts.URL, extName))
		app := getApp("", "")
		app.Status.Resources[0].Name = "something-else"
		f.appGetterMock.On("Get", mock.Anything, mock.Anything).Return(app, nil)

		// when
		resp, err := http.DefaultClient.Do(r)

		// then
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		actual := strings.TrimSuffix(string(body), "\n")
		assert.Contains(t, actual, "does not belong to the application")
	})
}

func getExtensionConfig(name, url string) string {
	cfg := `
extensions:
- name: %s
  backend:
    services:
    - url: %s
`
	return fmt.Sprintf(cfg, name, url)
}

func getExtensionConfigWith2Backends(name, url1, clus1, url2, clus2 string) string {
	cfg := `
extensions:
- name: %s
  backend:
    services:
    - url: %s
      cluster: %s
    - url: %s
      cluster: %s
`
	// second extension is configured with the cluster url rather
	// than the cluster name so we can validate that both use-cases
	// are working
	return fmt.Sprintf(cfg, name, url1, clus1, url2, url2)
}

func getExtensionConfigString() string {
	return `
extensions:
- name: external-backend
  backend:
    services:
    - url: https://httpbin.org
- name: some-backend
  backend:
    services:
    - url: http://localhost:7777
`
}

func getExtensionConfigNoName() string {
	return `
extensions:
- backend:
    services:
    - url: https://httpbin.org
`
}
func getExtensionConfigInvalidName() string {
	return `
extensions:
- name: invalid/name
  backend:
    services:
    - url: https://httpbin.org
`
}

func getExtensionConfigNoURL() string {
	return `
extensions:
- name: some-backend
  backend:
    services:
    - cluster: some-cluster
`
}
