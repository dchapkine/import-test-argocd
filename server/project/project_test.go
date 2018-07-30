package project

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/argoproj/argo-cd/common"
	"github.com/argoproj/argo-cd/pkg/apis/application/v1alpha1"
	apps "github.com/argoproj/argo-cd/pkg/client/clientset/versioned/fake"
	"github.com/argoproj/argo-cd/test"
	"github.com/argoproj/argo-cd/util"
	jwtUtil "github.com/argoproj/argo-cd/util/jwt"
	"github.com/argoproj/argo-cd/util/rbac"
	"github.com/argoproj/argo-cd/util/session"
	"github.com/argoproj/argo-cd/util/settings"
)

func TestProjectServer(t *testing.T) {
	enforcer := rbac.NewEnforcer(fake.NewSimpleClientset(), nil, "default", common.ArgoCDRBACConfigMapName, nil)
	enforcer.SetBuiltinPolicy(test.BuiltinPolicy)
	enforcer.SetDefaultRole("role:admin")
	existingProj := v1alpha1.AppProject{
		ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "default"},
		Spec: v1alpha1.AppProjectSpec{
			Destinations: []v1alpha1.ApplicationDestination{
				{Namespace: "ns1", Server: "https://server1"},
				{Namespace: "ns2", Server: "https://server2"},
			},
			SourceRepos: []string{"https://github.com/argoproj/argo-cd.git"},
		},
	}

	t.Run("TestRemoveDestinationSuccessful", func(t *testing.T) {
		existingApp := v1alpha1.Application{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "default"},
			Spec:       v1alpha1.ApplicationSpec{Project: "test", Destination: v1alpha1.ApplicationDestination{Namespace: "ns3", Server: "https://server3"}},
		}

		projectServer := NewServer("default", fake.NewSimpleClientset(), apps.NewSimpleClientset(&existingProj, &existingApp), enforcer, util.NewKeyLock(), nil)

		updatedProj := existingProj.DeepCopy()
		updatedProj.Spec.Destinations = updatedProj.Spec.Destinations[1:]

		_, err := projectServer.Update(context.Background(), &ProjectUpdateRequest{Project: updatedProj})

		assert.Nil(t, err)
	})

	t.Run("TestRemoveDestinationUsedByApp", func(t *testing.T) {
		existingApp := v1alpha1.Application{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "default"},
			Spec:       v1alpha1.ApplicationSpec{Project: "test", Destination: v1alpha1.ApplicationDestination{Namespace: "ns1", Server: "https://server1"}},
		}

		projectServer := NewServer("default", fake.NewSimpleClientset(), apps.NewSimpleClientset(&existingProj, &existingApp), enforcer, util.NewKeyLock(), nil)

		updatedProj := existingProj.DeepCopy()
		updatedProj.Spec.Destinations = updatedProj.Spec.Destinations[1:]

		_, err := projectServer.Update(context.Background(), &ProjectUpdateRequest{Project: updatedProj})

		assert.NotNil(t, err)
		assert.Equal(t, codes.InvalidArgument, grpc.Code(err))
	})

	t.Run("TestRemoveSourceSuccessful", func(t *testing.T) {
		existingApp := v1alpha1.Application{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "default"},
			Spec:       v1alpha1.ApplicationSpec{Project: "test"},
		}

		projectServer := NewServer("default", fake.NewSimpleClientset(), apps.NewSimpleClientset(&existingProj, &existingApp), enforcer, util.NewKeyLock(), nil)

		updatedProj := existingProj.DeepCopy()
		updatedProj.Spec.SourceRepos = []string{}

		_, err := projectServer.Update(context.Background(), &ProjectUpdateRequest{Project: updatedProj})

		assert.Nil(t, err)
	})

	t.Run("TestRemoveSourceUsedByApp", func(t *testing.T) {
		existingApp := v1alpha1.Application{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "default"},
			Spec:       v1alpha1.ApplicationSpec{Project: "test", Source: v1alpha1.ApplicationSource{RepoURL: "https://github.com/argoproj/argo-cd.git"}},
		}

		projectServer := NewServer("default", fake.NewSimpleClientset(), apps.NewSimpleClientset(&existingProj, &existingApp), enforcer, util.NewKeyLock(), nil)

		updatedProj := existingProj.DeepCopy()
		updatedProj.Spec.SourceRepos = []string{}

		_, err := projectServer.Update(context.Background(), &ProjectUpdateRequest{Project: updatedProj})

		assert.NotNil(t, err)
		assert.Equal(t, codes.InvalidArgument, grpc.Code(err))
	})

	t.Run("TestDeleteProjectSuccessful", func(t *testing.T) {
		projectServer := NewServer("default", fake.NewSimpleClientset(), apps.NewSimpleClientset(&existingProj), enforcer, util.NewKeyLock(), nil)

		_, err := projectServer.Delete(context.Background(), &ProjectQuery{Name: "test"})

		assert.Nil(t, err)
	})

	t.Run("TestDeleteProjectReferencedByApp", func(t *testing.T) {
		existingApp := v1alpha1.Application{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "default"},
			Spec:       v1alpha1.ApplicationSpec{Project: "test"},
		}

		projectServer := NewServer("default", fake.NewSimpleClientset(), apps.NewSimpleClientset(&existingProj, &existingApp), enforcer, util.NewKeyLock(), nil)

		_, err := projectServer.Delete(context.Background(), &ProjectQuery{Name: "test"})

		assert.NotNil(t, err)
		assert.Equal(t, codes.InvalidArgument, grpc.Code(err))
	})

	t.Run("TestCreateTokenSuccesfully", func(t *testing.T) {
		sessionMgr := session.NewSessionManager(&settings.ArgoCDSettings{})
		projWithoutToken := existingProj.DeepCopy()
		projectServer := NewServer("default", fake.NewSimpleClientset(), apps.NewSimpleClientset(projWithoutToken), enforcer, util.NewKeyLock(), sessionMgr)
		token := &v1alpha1.ProjectToken{Name: "test"}
		tokenResponse, err := projectServer.CreateToken(context.Background(), &ProjectTokenCreateRequest{Project: projWithoutToken, Token: token})
		assert.Nil(t, err)
		claims, err := sessionMgr.Parse(tokenResponse.Token)
		assert.Nil(t, err)

		mapClaims, err := jwtUtil.MapClaims(claims)
		subject, ok := mapClaims["sub"].(string)
		assert.True(t, ok)
		assert.Equal(t, "proj:test:test", subject)
		assert.Nil(t, err)
	})
	t.Run("TestCreateDuplicateTokenFailure", func(t *testing.T) {
		sessionMgr := session.NewSessionManager(&settings.ArgoCDSettings{})
		projWithToken := existingProj.DeepCopy()
		token := v1alpha1.ProjectToken{Name: "test"}
		projWithToken.Spec.Tokens = append(projWithToken.Spec.Tokens, token)
		projectServer := NewServer("default", fake.NewSimpleClientset(), apps.NewSimpleClientset(projWithToken), enforcer, util.NewKeyLock(), sessionMgr)
		_, err := projectServer.CreateToken(context.Background(), &ProjectTokenCreateRequest{Project: projWithToken, Token: &token})
		assert.EqualError(t, err, "rpc error: code = AlreadyExists desc = 'test' token already exist for project 'test'")
	})

	t.Run("TestCreateTokenPolicySuccessfully", func(t *testing.T) {
		action := "create"
		object := "testObject"
		permission := "allow"
		projWithToken := existingProj.DeepCopy()
		token := v1alpha1.ProjectToken{Name: "test"}
		projWithToken.Spec.Tokens = append(projWithToken.Spec.Tokens, token)
		projectServer := NewServer("default", fake.NewSimpleClientset(), apps.NewSimpleClientset(projWithToken), enforcer, util.NewKeyLock(), nil)
		request := &ProjectTokenPolicyCreateRequest{Project: projWithToken, Token: token.Name, Action: action, Object: object, Permission: permission}
		_, err := projectServer.CreateTokenPolicy(context.Background(), request)
		assert.Nil(t, err)
		t.Log(projWithToken.Spec.Tokens[0].Policies[0])
		expectedPolicy := fmt.Sprintf("p, proj:%s:%s, projects, %s, %s/%s", projWithToken.Name, token.Name, action, projWithToken.Name, object)
		assert.Equal(t, projWithToken.Spec.Tokens[0].Policies[0], expectedPolicy)
	})

	t.Run("TestCreateTokenPolicyOnNonExistingTokenFailure", func(t *testing.T) {
		action := "create"
		object := "testObject"
		permission := "allow"

		token := v1alpha1.ProjectToken{Name: "test"}
		projectServer := NewServer("default", fake.NewSimpleClientset(), apps.NewSimpleClientset(&existingProj), enforcer, util.NewKeyLock(), nil)
		request := &ProjectTokenPolicyCreateRequest{Project: &existingProj, Token: token.Name, Action: action, Object: object, Permission: permission}
		_, err := projectServer.CreateTokenPolicy(context.Background(), request)
		assert.EqualError(t, err, "rpc error: code = NotFound desc = 'test' token was not found in the project 'test'")

	})
}
