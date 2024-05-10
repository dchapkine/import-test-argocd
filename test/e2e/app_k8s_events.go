package e2e

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	. "github.com/argoproj/argo-cd/v2/test/e2e/fixture"
	. "github.com/argoproj/argo-cd/v2/test/e2e/fixture/app"
)

// resource.eventLabelKeys keys set in argocd-cm
func TestLabelsOnAppK8sEvents(t *testing.T) {
	expectedLabels := map[string]string{"app": "test", "env": "dev"}

	Given(t).
		Timeout(60).
		Path("two-nice-pods").
		When().
		SetParamInSettingConfigMap("resource.eventLabelKeys", "app,env").
		CreateApp("--label=app=test", "--label=env=dev", "--label=tier=ui").
		Sync().
		Then().
		Expect(SyncStatusIs(SyncStatusCodeSynced)).
		And(func(app *Application) {
			events, err := KubeClientset.CoreV1().Events(app.Namespace).List(context.Background(), metav1.ListOptions{
				FieldSelector: fmt.Sprintf("involvedObject.name=%s,involvedObject.kind=Application", app.Name),
			})
			assert.NoError(t, err)
			for _, event := range events.Items {
				for k, v := range event.Labels {
					ev, found := expectedLabels[k]
					assert.True(t, found)
					assert.Equal(t, ev, v)
				}
			}
		})
}

// resource.eventLabelKeys keys not set in argocd-cm
func TestNoLabelsOnAppK8sEvents(t *testing.T) {
	Given(t).
		Timeout(60).
		Path("two-nice-pods").
		When().
		CreateApp("--label=app=test", "--label=env=dev", "--label=tier=ui").
		Sync().
		Then().
		Expect(SyncStatusIs(SyncStatusCodeSynced)).
		And(func(app *Application) {
			events, err := KubeClientset.CoreV1().Events(app.Namespace).List(context.Background(), metav1.ListOptions{
				FieldSelector: fmt.Sprintf("involvedObject.name=%s,involvedObject.kind=Application", app.Name),
			})
			assert.NoError(t, err)
			for _, event := range events.Items {
				assert.Nil(t, event.Labels)
			}
		})
}
