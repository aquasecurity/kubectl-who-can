package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	authz "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clientauthz "k8s.io/client-go/kubernetes/typed/authorization/v1"
	clienttesting "k8s.io/client-go/testing"
)

func TestIsAllowed(t *testing.T) {

	data := []struct {
		scenario     string
		reactionFunc clienttesting.ReactionFunc

		allowed bool
		err     error
	}{
		{
			scenario:     "Should return true when SSAR's allowed property is true",
			reactionFunc: newSelfSubjectAccessReviewsReactionFunc(true, nil),
			allowed:      true,
		},
		{
			scenario:     "Should return false when SSAR's allowed property is false",
			reactionFunc: newSelfSubjectAccessReviewsReactionFunc(false, nil),
			allowed:      false,
		},
		{
			scenario:     "Should return error when API request fails",
			reactionFunc: newSelfSubjectAccessReviewsReactionFunc(false, errors.New("api is down")),
			err:          errors.New("api is down"),
		},
	}

	for _, tt := range data {
		t.Run(tt.scenario, func(t *testing.T) {
			// given
			client := newClient(tt.reactionFunc)
			ctx := context.Background()
			// when
			allowed, err := NewAccessChecker(client).IsAllowedTo(ctx, "list", "roles", "", metav1.CreateOptions{})

			// then
			assert.Equal(t, tt.allowed, allowed)
			assert.Equal(t, tt.err, err)
		})
	}

}

func newClient(reaction clienttesting.ReactionFunc) clientauthz.SelfSubjectAccessReviewInterface {
	client := fake.NewSimpleClientset()
	client.Fake.PrependReactor("create", "selfsubjectaccessreviews", reaction)
	return client.AuthorizationV1().SelfSubjectAccessReviews()
}

func newSelfSubjectAccessReviewsReactionFunc(allowed bool, err error) clienttesting.ReactionFunc {
	return func(action clienttesting.Action) (bool, runtime.Object, error) {
		sar := &authz.SelfSubjectAccessReview{
			Status: authz.SubjectAccessReviewStatus{
				Allowed: allowed,
			},
		}
		return true, sar, err
	}
}
