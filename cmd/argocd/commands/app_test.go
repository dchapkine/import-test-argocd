package commands

import (
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"

	"github.com/argoproj/gitops-engine/pkg/health"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	argocdclient "github.com/argoproj/argo-cd/v2/pkg/apiclient"

	"github.com/stretchr/testify/assert"

	"github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
)

func TestFindRevisionHistoryWithoutPassedId(t *testing.T) {

	histories := v1alpha1.RevisionHistories{}

	histories = append(histories, v1alpha1.RevisionHistory{ID: 1})
	histories = append(histories, v1alpha1.RevisionHistory{ID: 2})
	histories = append(histories, v1alpha1.RevisionHistory{ID: 3})

	status := v1alpha1.ApplicationStatus{
		Resources:      nil,
		Sync:           v1alpha1.SyncStatus{},
		Health:         v1alpha1.HealthStatus{},
		History:        histories,
		Conditions:     nil,
		ReconciledAt:   nil,
		OperationState: nil,
		ObservedAt:     nil,
		SourceType:     "",
		Summary:        v1alpha1.ApplicationSummary{},
	}

	application := v1alpha1.Application{
		Status: status,
	}

	history, err := findRevisionHistory(&application, -1)

	if err != nil {
		t.Fatal("Find revision history should fail without errors")
	}

	if history == nil {
		t.Fatal("History should be found")
	}

}

func TestDefaultWaitOptions(t *testing.T) {
	watch := watchOpts{
		sync:      false,
		health:    false,
		operation: false,
		suspended: false,
	}
	opts := getWatchOpts(watch)
	assert.Equal(t, true, opts.sync)
	assert.Equal(t, true, opts.health)
	assert.Equal(t, true, opts.operation)
	assert.Equal(t, false, opts.suspended)
}

func TestOverrideWaitOptions(t *testing.T) {
	watch := watchOpts{
		sync:      true,
		health:    false,
		operation: false,
		suspended: false,
	}
	opts := getWatchOpts(watch)
	assert.Equal(t, true, opts.sync)
	assert.Equal(t, false, opts.health)
	assert.Equal(t, false, opts.operation)
	assert.Equal(t, false, opts.suspended)
}

func TestFindRevisionHistoryWithoutPassedIdAndEmptyHistoryList(t *testing.T) {

	histories := v1alpha1.RevisionHistories{}

	status := v1alpha1.ApplicationStatus{
		Resources:      nil,
		Sync:           v1alpha1.SyncStatus{},
		Health:         v1alpha1.HealthStatus{},
		History:        histories,
		Conditions:     nil,
		ReconciledAt:   nil,
		OperationState: nil,
		ObservedAt:     nil,
		SourceType:     "",
		Summary:        v1alpha1.ApplicationSummary{},
	}

	application := v1alpha1.Application{
		Status: status,
	}

	history, err := findRevisionHistory(&application, -1)

	if err == nil {
		t.Fatal("Find revision history should fail with errors")
	}

	if history != nil {
		t.Fatal("History should be empty")
	}

	if err.Error() != "Application '' should have at least two successful deployments" {
		t.Fatal("Find revision history should fail with correct error message")
	}

}

func TestFindRevisionHistoryWithPassedId(t *testing.T) {

	histories := v1alpha1.RevisionHistories{}

	histories = append(histories, v1alpha1.RevisionHistory{ID: 1})
	histories = append(histories, v1alpha1.RevisionHistory{ID: 2})
	histories = append(histories, v1alpha1.RevisionHistory{ID: 3, Revision: "123"})

	status := v1alpha1.ApplicationStatus{
		Resources:      nil,
		Sync:           v1alpha1.SyncStatus{},
		Health:         v1alpha1.HealthStatus{},
		History:        histories,
		Conditions:     nil,
		ReconciledAt:   nil,
		OperationState: nil,
		ObservedAt:     nil,
		SourceType:     "",
		Summary:        v1alpha1.ApplicationSummary{},
	}

	application := v1alpha1.Application{
		Status: status,
	}

	history, err := findRevisionHistory(&application, 3)

	if err != nil {
		t.Fatal("Find revision history should fail without errors")
	}

	if history == nil {
		t.Fatal("History should be found")
	}

	if history.Revision != "123" {
		t.Fatal("Failed to find correct history with correct revision")
	}

}

func TestFindRevisionHistoryWithPassedIdThatNotExist(t *testing.T) {

	histories := v1alpha1.RevisionHistories{}

	histories = append(histories, v1alpha1.RevisionHistory{ID: 1})
	histories = append(histories, v1alpha1.RevisionHistory{ID: 2})
	histories = append(histories, v1alpha1.RevisionHistory{ID: 3, Revision: "123"})

	status := v1alpha1.ApplicationStatus{
		Resources:      nil,
		Sync:           v1alpha1.SyncStatus{},
		Health:         v1alpha1.HealthStatus{},
		History:        histories,
		Conditions:     nil,
		ReconciledAt:   nil,
		OperationState: nil,
		ObservedAt:     nil,
		SourceType:     "",
		Summary:        v1alpha1.ApplicationSummary{},
	}

	application := v1alpha1.Application{
		Status: status,
	}

	history, err := findRevisionHistory(&application, 4)

	if err == nil {
		t.Fatal("Find revision history should fail with errors")
	}

	if history != nil {
		t.Fatal("History should be not found")
	}

	if err.Error() != "Application '' does not have deployment id '4' in history\n" {
		t.Fatal("Find revision history should fail with correct error message")
	}

}

func TestFilterResources(t *testing.T) {

	t.Run("Filter by ns", func(t *testing.T) {

		resources := []*v1alpha1.ResourceDiff{
			{
				LiveState: "{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"name\":\"test-helm-guestbook\",\"namespace\":\"argocd\"},\"spec\":{\"selector\":{\"app\":\"helm-guestbook\",\"release\":\"test\"},\"sessionAffinity\":\"None\",\"type\":\"ClusterIP\"},\"status\":{\"loadBalancer\":{}}}",
			},
			{
				LiveState: "{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"name\":\"test-helm-guestbook\",\"namespace\":\"ns\"},\"spec\":{\"selector\":{\"app\":\"helm-guestbook\",\"release\":\"test\"},\"sessionAffinity\":\"None\",\"type\":\"ClusterIP\"},\"status\":{\"loadBalancer\":{}}}",
			},
		}

		filteredResources := filterResources(false, resources, "g", "Service", "ns", "test-helm-guestbook", true)
		if len(filteredResources) != 1 {
			t.Fatal("Incorrect number of resources after filter")
		}

	})

	t.Run("Filter by kind", func(t *testing.T) {

		resources := []*v1alpha1.ResourceDiff{
			{
				LiveState: "{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"name\":\"test-helm-guestbook\",\"namespace\":\"argocd\"},\"spec\":{\"selector\":{\"app\":\"helm-guestbook\",\"release\":\"test\"},\"sessionAffinity\":\"None\",\"type\":\"ClusterIP\"},\"status\":{\"loadBalancer\":{}}}",
			},
			{
				LiveState: "{\"apiVersion\":\"v1\",\"kind\":\"Deployment\",\"metadata\":{\"name\":\"test-helm-guestbook\",\"namespace\":\"argocd\"},\"spec\":{\"selector\":{\"app\":\"helm-guestbook\",\"release\":\"test\"},\"sessionAffinity\":\"None\",\"type\":\"ClusterIP\"},\"status\":{\"loadBalancer\":{}}}",
			},
		}

		filteredResources := filterResources(false, resources, "g", "Deployment", "argocd", "test-helm-guestbook", true)
		if len(filteredResources) != 1 {
			t.Fatal("Incorrect number of resources after filter")
		}

	})

	t.Run("Filter by name", func(t *testing.T) {

		resources := []*v1alpha1.ResourceDiff{
			{
				LiveState: "{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"name\":\"test-helm-guestbook\",\"namespace\":\"argocd\"},\"spec\":{\"selector\":{\"app\":\"helm-guestbook\",\"release\":\"test\"},\"sessionAffinity\":\"None\",\"type\":\"ClusterIP\"},\"status\":{\"loadBalancer\":{}}}",
			},
			{
				LiveState: "{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"name\":\"test-helm\",\"namespace\":\"argocd\"},\"spec\":{\"selector\":{\"app\":\"helm-guestbook\",\"release\":\"test\"},\"sessionAffinity\":\"None\",\"type\":\"ClusterIP\"},\"status\":{\"loadBalancer\":{}}}",
			},
		}

		filteredResources := filterResources(false, resources, "g", "Service", "argocd", "test-helm", true)
		if len(filteredResources) != 1 {
			t.Fatal("Incorrect number of resources after filter")
		}

	})
}

func TestFormatSyncPolicy(t *testing.T) {

	t.Run("Policy not defined", func(t *testing.T) {
		app := v1alpha1.Application{}

		policy := formatSyncPolicy(app)

		if policy != "<none>" {
			t.Fatalf("Incorrect policy %q, should be <none>", policy)
		}
	})

	t.Run("Auto policy", func(t *testing.T) {
		app := v1alpha1.Application{
			Spec: v1alpha1.ApplicationSpec{
				SyncPolicy: &v1alpha1.SyncPolicy{
					Automated: &v1alpha1.SyncPolicyAutomated{},
				},
			},
		}

		policy := formatSyncPolicy(app)

		if policy != "Auto" {
			t.Fatalf("Incorrect policy %q, should be Auto", policy)
		}
	})

	t.Run("Auto policy with prune", func(t *testing.T) {
		app := v1alpha1.Application{
			Spec: v1alpha1.ApplicationSpec{
				SyncPolicy: &v1alpha1.SyncPolicy{
					Automated: &v1alpha1.SyncPolicyAutomated{
						Prune: true,
					},
				},
			},
		}

		policy := formatSyncPolicy(app)

		if policy != "Auto-Prune" {
			t.Fatalf("Incorrect policy %q, should be Auto-Prune", policy)
		}
	})

}

func TestFormatConditionSummary(t *testing.T) {
	t.Run("No conditions are defined", func(t *testing.T) {
		app := v1alpha1.Application{
			Spec: v1alpha1.ApplicationSpec{
				SyncPolicy: &v1alpha1.SyncPolicy{
					Automated: &v1alpha1.SyncPolicyAutomated{
						Prune: true,
					},
				},
			},
		}

		summary := formatConditionsSummary(app)
		if summary != "<none>" {
			t.Fatalf("Incorrect summary %q, should be <none>", summary)
		}
	})

	t.Run("Few conditions are defined", func(t *testing.T) {
		app := v1alpha1.Application{
			Status: v1alpha1.ApplicationStatus{
				Conditions: []v1alpha1.ApplicationCondition{
					{
						Type: "type1",
					},
					{
						Type: "type1",
					},
					{
						Type: "type2",
					},
				},
			},
		}

		summary := formatConditionsSummary(app)
		if summary != "type1(2),type2" && summary != "type2,type1(2)" {
			t.Fatalf("Incorrect summary %q, should be type1(2),type2", summary)
		}
	})
}

func TestPrintOperationResult(t *testing.T) {
	t.Run("Operation state is empty", func(t *testing.T) {
		output, _ := captureOutput(func() error {
			printOperationResult(nil)
			return nil
		})

		if output != "" {
			t.Fatalf("Incorrect print operation output %q, should be ''", output)
		}
	})

	t.Run("Operation state sync result is not empty", func(t *testing.T) {
		time := metav1.Date(2020, time.November, 10, 23, 0, 0, 0, time.UTC)
		output, _ := captureOutput(func() error {
			printOperationResult(&v1alpha1.OperationState{
				SyncResult: &v1alpha1.SyncOperationResult{Revision: "revision"},
				FinishedAt: &time,
			})
			return nil
		})

		expectation := "Operation:          Sync\nSync Revision:      revision\nPhase:              \nStart:              0001-01-01 00:00:00 +0000 UTC\nFinished:           2020-11-10 23:00:00 +0000 UTC\nDuration:           2333448h16m18.871345152s\n"
		if output != expectation {
			t.Fatalf("Incorrect print operation output %q, should be %q", output, expectation)
		}
	})

	t.Run("Operation state sync result with message is not empty", func(t *testing.T) {
		time := metav1.Date(2020, time.November, 10, 23, 0, 0, 0, time.UTC)
		output, _ := captureOutput(func() error {
			printOperationResult(&v1alpha1.OperationState{
				SyncResult: &v1alpha1.SyncOperationResult{Revision: "revision"},
				FinishedAt: &time,
				Message:    "test",
			})
			return nil
		})

		expectation := "Operation:          Sync\nSync Revision:      revision\nPhase:              \nStart:              0001-01-01 00:00:00 +0000 UTC\nFinished:           2020-11-10 23:00:00 +0000 UTC\nDuration:           2333448h16m18.871345152s\nMessage:            test\n"
		if output != expectation {
			t.Fatalf("Incorrect print operation output %q, should be %q", output, expectation)
		}
	})
}

func TestPrintApplicationHistoryTable(t *testing.T) {
	histories := []v1alpha1.RevisionHistory{
		{
			ID: 1,
			Source: v1alpha1.ApplicationSource{
				TargetRevision: "1",
			},
		},
		{
			ID: 2,
			Source: v1alpha1.ApplicationSource{
				TargetRevision: "2",
			},
		},
		{
			ID: 3,
			Source: v1alpha1.ApplicationSource{
				TargetRevision: "3",
			},
		},
	}

	output, _ := captureOutput(func() error {
		printApplicationHistoryTable(histories)
		return nil
	})

	expectation := "ID  DATE                           REVISION\n1   0001-01-01 00:00:00 +0000 UTC  1\n2   0001-01-01 00:00:00 +0000 UTC  2\n3   0001-01-01 00:00:00 +0000 UTC  3\n"

	if output != expectation {
		t.Fatalf("Incorrect print operation output %q, should be %q", output, expectation)
	}
}

func TestPrintAppSummaryTable(t *testing.T) {
	output, _ := captureOutput(func() error {
		app := &v1alpha1.Application{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "argocd",
			},
			Spec: v1alpha1.ApplicationSpec{
				SyncPolicy: &v1alpha1.SyncPolicy{
					Automated: &v1alpha1.SyncPolicyAutomated{
						Prune: true,
					},
				},
				Project:     "default",
				Destination: v1alpha1.ApplicationDestination{Server: "local", Namespace: "argocd"},
				Source: v1alpha1.ApplicationSource{
					RepoURL:        "test",
					TargetRevision: "master",
					Path:           "/test",
					Helm: &v1alpha1.ApplicationSourceHelm{
						ValueFiles: []string{"path1", "path2"},
					},
					Kustomize: &v1alpha1.ApplicationSourceKustomize{NamePrefix: "prefix"},
				},
			},
			Status: v1alpha1.ApplicationStatus{
				Sync: v1alpha1.SyncStatus{
					Status: v1alpha1.SyncStatusCodeOutOfSync,
				},
				Health: v1alpha1.HealthStatus{
					Status:  health.HealthStatusProgressing,
					Message: "health-message",
				},
			},
		}

		windows := &v1alpha1.SyncWindows{}

		printAppSummaryTable(app, "url", windows)
		return nil
	})

	expectation := "Name:               test\nProject:            default\nServer:             local\nNamespace:          argocd\nURL:                url\nRepo:               test\nTarget:             master\nPath:               /test\nHelm Values:        path1,path2\nName Prefix:        prefix\nSyncWindow:         Sync Allowed\nSync Policy:        Automated (Prune)\nSync Status:        OutOfSync from master\nHealth Status:      Progressing (health-message)\n"
	if output != expectation {
		t.Fatalf("Incorrect print app summary output %q, should be %q", output, expectation)
	}
}

func TestPrintAppConditions(t *testing.T) {
	output, _ := captureOutput(func() error {
		app := &v1alpha1.Application{
			Status: v1alpha1.ApplicationStatus{
				Conditions: []v1alpha1.ApplicationCondition{
					{
						Type:    v1alpha1.ApplicationConditionDeletionError,
						Message: "test",
					},
					{
						Type:    v1alpha1.ApplicationConditionExcludedResourceWarning,
						Message: "test2",
					},
					{
						Type:    v1alpha1.ApplicationConditionRepeatedResourceWarning,
						Message: "test3",
					},
				},
			},
		}
		printAppConditions(os.Stdout, app)
		return nil
	})
	expectation := "CONDITION\tMESSAGE\tLAST TRANSITION\nDeletionError\ttest\t<nil>\nExcludedResourceWarning\ttest2\t<nil>\nRepeatedResourceWarning\ttest3\t<nil>\n"
	if output != expectation {
		t.Fatalf("Incorrect print app conditions output %q, should be %q", output, expectation)
	}
}

func TestPrintParams(t *testing.T) {
	output, _ := captureOutput(func() error {
		app := &v1alpha1.Application{
			Spec: v1alpha1.ApplicationSpec{
				Source: v1alpha1.ApplicationSource{
					Helm: &v1alpha1.ApplicationSourceHelm{
						Parameters: []v1alpha1.HelmParameter{
							{
								Name:  "name1",
								Value: "value1",
							},
							{
								Name:  "name2",
								Value: "value2",
							},
							{
								Name:  "name3",
								Value: "value3",
							},
						},
					},
				},
			},
		}
		printParams(app)
		return nil
	})
	expectation := "\n\nNAME   VALUE\nname1  value1\nname2  value2\nname3  value3\n"
	if output != expectation {
		t.Fatalf("Incorrect print params output %q, should be %q", output, expectation)
	}
}

func TestAppUrlDefault(t *testing.T) {
	t.Run("Plain text", func(t *testing.T) {
		result := appURLDefault(argocdclient.NewClientOrDie(&argocdclient.ClientOptions{
			ServerAddr: "localhost:80",
			PlainText:  true,
		}), "test")
		expectation := "http://localhost:80/applications/test"
		if result != expectation {
			t.Fatalf("Incorrect url %q, should be %q", result, expectation)
		}
	})
	t.Run("https", func(t *testing.T) {
		result := appURLDefault(argocdclient.NewClientOrDie(&argocdclient.ClientOptions{
			ServerAddr: "localhost:443",
			PlainText:  false,
		}), "test")
		expectation := "https://localhost/applications/test"
		if result != expectation {
			t.Fatalf("Incorrect url %q, should be %q", result, expectation)
		}
	})
}

func TestTruncateString(t *testing.T) {
	result := truncateString("argocdtool", 2)
	expectation := "ar..."
	if result != expectation {
		t.Fatalf("Incorrect truncate string %q, should be %q", result, expectation)
	}
}

func TestGetService(t *testing.T) {
	t.Run("Server", func(t *testing.T) {
		app := &v1alpha1.Application{
			Spec: v1alpha1.ApplicationSpec{
				Destination: v1alpha1.ApplicationDestination{
					Server: "test-server",
				},
			},
		}
		result := getServer(app)
		expectation := "test-server"
		if result != expectation {
			t.Fatalf("Incorrect server %q, should be %q", result, expectation)
		}
	})
	t.Run("Name", func(t *testing.T) {
		app := &v1alpha1.Application{
			Spec: v1alpha1.ApplicationSpec{
				Destination: v1alpha1.ApplicationDestination{
					Name: "test-name",
				},
			},
		}
		result := getServer(app)
		expectation := "test-name"
		if result != expectation {
			t.Fatalf("Incorrect server name %q, should be %q", result, expectation)
		}
	})
}

func TestTargetObjects(t *testing.T) {
	resources := []*v1alpha1.ResourceDiff{
		{
			TargetState: "{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"name\":\"test-helm-guestbook\",\"namespace\":\"argocd\"},\"spec\":{\"selector\":{\"app\":\"helm-guestbook\",\"release\":\"test\"},\"sessionAffinity\":\"None\",\"type\":\"ClusterIP\"},\"status\":{\"loadBalancer\":{}}}",
		},
		{
			TargetState: "{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"name\":\"test-helm-guestbook\",\"namespace\":\"ns\"},\"spec\":{\"selector\":{\"app\":\"helm-guestbook\",\"release\":\"test\"},\"sessionAffinity\":\"None\",\"type\":\"ClusterIP\"},\"status\":{\"loadBalancer\":{}}}",
		},
	}
	objects, err := targetObjects(resources)
	if err != nil {
		t.Fatal("operation should finish without error")
	}

	if len(objects) != 2 {
		t.Fatalf("incorrect number of objects %v, should be 2", len(objects))
	}

	if objects[0].GetName() != "test-helm-guestbook" {
		t.Fatalf("incorrect name %q, should be %q", objects[0].GetName(), "test-helm-guestbook")
	}

}

func TestPrintApplicationNames(t *testing.T) {
	output, _ := captureOutput(func() error {
		app := &v1alpha1.Application{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test",
			},
		}
		printApplicationNames([]v1alpha1.Application{*app, *app})
		return nil
	})
	expectation := "test\ntest\n"
	if output != expectation {
		t.Fatalf("Incorrect print params output %q, should be %q", output, expectation)
	}
}

func Test_unset(t *testing.T) {
	yaml, err := v1alpha1.NewStringOrObjectFromYAML([]byte("some: yaml"))
	require.NoError(t, err)
	kustomizeApp := v1alpha1.Application{
		Spec: v1alpha1.ApplicationSpec{
			Source: v1alpha1.ApplicationSource{
				Kustomize: &v1alpha1.ApplicationSourceKustomize{
					NamePrefix: "some-prefix",
					NameSuffix: "some-suffix",
					Version:    "123",
					Images: v1alpha1.KustomizeImages{
						"old1=new:tag",
						"old2=new:tag",
					},
				},
			},
		},
	}

	assert.Equal(t, "some-prefix", kustomizeApp.Spec.Source.Kustomize.NamePrefix)
	unset(&kustomizeApp, unsetOpts{namePrefix: true})
	assert.Equal(t, "", kustomizeApp.Spec.Source.Kustomize.NamePrefix)

	assert.Equal(t, "some-suffix", kustomizeApp.Spec.Source.Kustomize.NameSuffix)
	unset(&kustomizeApp, unsetOpts{nameSuffix: true})
	assert.Equal(t, "", kustomizeApp.Spec.Source.Kustomize.NameSuffix)

	assert.Equal(t, "123", kustomizeApp.Spec.Source.Kustomize.Version)
	unset(&kustomizeApp, unsetOpts{kustomizeVersion: true})
	assert.Equal(t, "", kustomizeApp.Spec.Source.Kustomize.Version)

	assert.Equal(t, 2, len(kustomizeApp.Spec.Source.Kustomize.Images))
	unset(&kustomizeApp, unsetOpts{kustomizeImages: []string{"old1=new:tag"}})
	assert.Equal(t, 1, len(kustomizeApp.Spec.Source.Kustomize.Images))

	helmApp := v1alpha1.Application{
		Spec: v1alpha1.ApplicationSpec{
			Source: v1alpha1.ApplicationSource{
				Helm: &v1alpha1.ApplicationSourceHelm{
					IgnoreMissingValueFiles: true,
					Parameters: []v1alpha1.HelmParameter{
						{
							Name:  "name-1",
							Value: "value-1",
						},
						{
							Name:  "name-2",
							Value: "value-2",
						},
					},
					PassCredentials: true,
					Values:          *yaml,
					ValueFiles: []string{
						"values-1.yaml",
						"values-2.yaml",
					},
				},
			},
		},
	}

	assert.Equal(t, 2, len(helmApp.Spec.Source.Helm.Parameters))
	unset(&helmApp, unsetOpts{parameters: []string{"name-1"}})
	assert.Equal(t, 1, len(helmApp.Spec.Source.Helm.Parameters))

	assert.Equal(t, 2, len(helmApp.Spec.Source.Helm.ValueFiles))
	unset(&helmApp, unsetOpts{valuesFiles: []string{"values-1.yaml"}})
	assert.Equal(t, 1, len(helmApp.Spec.Source.Helm.ValueFiles))

	assert.Equal(t, "some: yaml\n", string(helmApp.Spec.Source.Helm.Values.YAML()))
	unset(&helmApp, unsetOpts{valuesLiteral: true})
	assert.Equal(t, "", string(helmApp.Spec.Source.Helm.Values.YAML()))

	assert.Equal(t, true, helmApp.Spec.Source.Helm.IgnoreMissingValueFiles)
	unset(&helmApp, unsetOpts{ignoreMissingValueFiles: true})
	assert.Equal(t, false, helmApp.Spec.Source.Helm.IgnoreMissingValueFiles)

	pluginApp := v1alpha1.Application{
		Spec: v1alpha1.ApplicationSpec{
			Source: v1alpha1.ApplicationSource{
				Plugin: &v1alpha1.ApplicationSourcePlugin{
					Env: v1alpha1.Env{
						{
							Name: "env-1",
							Value: "env-value-1",
						},
						{
							Name: "env-2",
							Value: "env-value-2",
						},
					},
				},
			},
		},
	}

	assert.Equal(t, 2, len(pluginApp.Spec.Source.Plugin.Env))
	unset(&pluginApp, unsetOpts{pluginEnvs: []string{"env-1"}})
	assert.Equal(t, 1, len(pluginApp.Spec.Source.Plugin.Env))
}
