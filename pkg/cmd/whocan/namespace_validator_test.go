package whocan

import (
	"errors"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	v12 "k8s.io/client-go/kubernetes/typed/core/v1"
	k8stesting "k8s.io/client-go/testing"
	"testing"
)

func TestNamespaceValidator_Validate(t *testing.T) {

	data := []struct {
		TestName string

		APIReturnedNamespace *v1.Namespace
		APIReturnedErr       error

		ExpectedErr error
	}{
		{
			TestName: "Should return error when getting namespace fails",

			APIReturnedNamespace: nil,
			APIReturnedErr:       errors.New("server is down"),

			ExpectedErr: errors.New("getting namespace: server is down"),
		}, {
			TestName: "Should return error when namespace does not exist",

			APIReturnedNamespace: nil,
			APIReturnedErr: &k8serrors.StatusError{
				ErrStatus: metav1.Status{
					Reason: metav1.StatusReasonNotFound,
				},
			},

			ExpectedErr: errors.New("\"my.namespace\" not found"),
		}, {
			TestName: "Should return error when namespace is not active",

			APIReturnedNamespace: &v1.Namespace{
				Status: v1.NamespaceStatus{
					Phase: v1.NamespaceTerminating,
				},
			},
			APIReturnedErr: nil,

			ExpectedErr: errors.New("invalid status: Terminating"),
		}, {
			TestName: "Should return nil when namespace is active",

			APIReturnedNamespace: &v1.Namespace{
				Status: v1.NamespaceStatus{
					Phase: v1.NamespaceActive,
				},
			},
			APIReturnedErr: nil,

			ExpectedErr: nil,
		},
	}

	for _, tt := range data {
		t.Run(tt.TestName, func(t *testing.T) {
			// given
			namespace := newNamespaces(newGetNamespacesReactionFunc(tt.APIReturnedNamespace, tt.APIReturnedErr))
			validator := NewNamespaceValidator(namespace)

			// when
			err := validator.Validate("my.namespace")

			// then
			assert.Equal(t, tt.ExpectedErr, err)
		})
	}

}

func newNamespaces(reaction k8stesting.ReactionFunc) v12.NamespaceInterface {
	client := fake.NewSimpleClientset()
	client.Fake.PrependReactor("get", "namespaces", reaction)
	return client.CoreV1().Namespaces()
}

func newGetNamespacesReactionFunc(ns *v1.Namespace, err error) k8stesting.ReactionFunc {
	return func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, ns, err
	}
}
