package cmd

import (
	"errors"
	"github.com/stretchr/testify/assert"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"testing"
)

func TestIsAllowed(t *testing.T) {

	data := []struct {
		name        string
		reactorFunc func(action k8stesting.Action) (bool, runtime.Object, error)

		allowed bool
		err     error
	}{
		{
			name:        "Should return true when SSAR's allowed property is true",
			reactorFunc: newSelfSubjectAccessReviewsReactorFunc(true, nil),
			allowed:     true,
		},
		{
			name:        "Should return false when SSAR's allowed property is false",
			reactorFunc: newSelfSubjectAccessReviewsReactorFunc(false, nil),
			allowed:     false,
		},
		{
			name:        "Should return error when API request fails",
			reactorFunc: newSelfSubjectAccessReviewsReactorFunc(false, errors.New("api is down")),
			err:         errors.New("api is down"),
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			// given
			client := newClient(tt.reactorFunc)

			// when
			allowed, err := NewAPIAccessChecker(client).IsAllowedTo("list", "roles")

			// then
			assert.Equal(t, tt.allowed, allowed)
			assert.Equal(t, tt.err, err)
		})
	}

}

func newClient(reactor func(action k8stesting.Action) (bool, runtime.Object, error)) kubernetes.Interface {
	client := fake.NewSimpleClientset()
	client.Fake.PrependReactor("create", "selfsubjectaccessreviews", reactor)
	return client
}

func newSelfSubjectAccessReviewsReactorFunc(allowed bool, err error) func(action k8stesting.Action) (bool, runtime.Object, error) {
	return func(action k8stesting.Action) (bool, runtime.Object, error) {
		sar := &authzv1.SelfSubjectAccessReview{
			Status: authzv1.SubjectAccessReviewStatus{
				Allowed: allowed,
			},
		}
		return true, sar, err
	}
}
