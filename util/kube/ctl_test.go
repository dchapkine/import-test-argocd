package kube

import (
	"io/ioutil"
	"testing"

	"github.com/argoproj/argo-cd/util"

	"github.com/ghodss/yaml"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestConvertToVersion(t *testing.T) {
	callbackExecuted := false
	closerExecuted := false
	kubectl := KubectlCmd{
		func(command string) (util.Closer, error) {
			callbackExecuted = true
			return util.NewCloser(func() error {
				closerExecuted = true
				return nil
			}), nil
		},
	}

	yamlBytes, err := ioutil.ReadFile("testdata/nginx.yaml")
	assert.Nil(t, err)
	var obj unstructured.Unstructured
	err = yaml.Unmarshal(yamlBytes, &obj)
	assert.Nil(t, err)

	// convert an extensions/v1beta1 object into an apps/v1
	newObj, err := kubectl.ConvertToVersion(&obj, "apps", "v1")
	assert.Nil(t, err)
	gvk := newObj.GroupVersionKind()
	assert.Equal(t, "apps", gvk.Group)
	assert.Equal(t, "v1", gvk.Version)
	assert.True(t, callbackExecuted)
	assert.True(t, closerExecuted)

	// converting it again should not have any affect
	newObj, err = kubectl.ConvertToVersion(&obj, "apps", "v1")
	assert.Nil(t, err)
	gvk = newObj.GroupVersionKind()
	assert.Equal(t, "apps", gvk.Group)
	assert.Equal(t, "v1", gvk.Version)
}

func TestRunKubectl(t *testing.T) {
	callbackExecuted := false
	closerExecuted := false
	kubectl := KubectlCmd{
		func(command string) (util.Closer, error) {
			callbackExecuted = true
			return util.NewCloser(func() error {
				closerExecuted = true
				return nil
			}), nil
		},
	}

	_, _ = kubectl.runKubectl("/dev/null", "default", []string{"command-name"}, nil, false)
	assert.True(t, callbackExecuted)
	assert.True(t, closerExecuted)
}

func TestVersion(t *testing.T) {
	ver, err := Version()
	assert.NoError(t, err)
	assert.True(t, semver.IsValid(ver))
}