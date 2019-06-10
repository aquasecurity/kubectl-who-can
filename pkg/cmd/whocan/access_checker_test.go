package whocan

import (
	"errors"
	"github.com/stretchr/testify/assert"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	v1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	k8stesting "k8s.io/client-go/testing"
	"testing"
)

func TestIsAllowed(t *testing.T) {

	data := []struct {
		scenario     string
		reactionFunc k8stesting.ReactionFunc

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

			// when
			allowed, err := NewAPIAccessChecker(client).IsAllowedTo("list", "roles", "")

			// then
			assert.Equal(t, tt.allowed, allowed)
			assert.Equal(t, tt.err, err)
		})
	}

}

func newClient(reaction k8stesting.ReactionFunc) v1.SelfSubjectAccessReviewInterface {
	client := fake.NewSimpleClientset()
	client.Fake.PrependReactor("create", "selfsubjectaccessreviews", reaction)
	return client.AuthorizationV1().SelfSubjectAccessReviews()
}

func newSelfSubjectAccessReviewsReactionFunc(allowed bool, err error) k8stesting.ReactionFunc {
	return func(action k8stesting.Action) (bool, runtime.Object, error) {
		sar := &authzv1.SelfSubjectAccessReview{
			Status: authzv1.SubjectAccessReviewStatus{
				Allowed: allowed,
			},
		}
		return true, sar, err
	}
}
