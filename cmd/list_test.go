package cmd

import (
	"errors"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clientTesting "k8s.io/client-go/testing"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
)

func TestMatch(t *testing.T) {
	r := make(roles, 1)
	entry := role{
		name:          "hello",
		isClusterRole: false,
	}
	r[entry] = struct{}{}

	rr := rbacv1.RoleRef{
		Kind: "Something else",
		Name: "hello",
	}
	if !r.match(&rr) {
		t.Error("Expected match")
	}

	rr.Kind = "ClusterRole"
	if r.match(&rr) {
		t.Error("Expected no match")
	}
}

func TestWhoCan_ValidateNamespace(t *testing.T) {

	t.Run("Should return error when getting namespace fails", func(t *testing.T) {
		// given
		client := fake.NewSimpleClientset()
		client.Fake.PrependReactor("get", "namespaces", func(action clientTesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("boom")
		})
		// and
		wc := whoCan{
			client: client,
		}
		// when
		err := wc.validateNamespace("foo")
		// then
		assert.EqualError(t, err, "getting namespace: boom")
	})

	t.Run("Should return error when namespace does not exist", func(t *testing.T) {
		// given
		client := fake.NewSimpleClientset()
		// and
		wc := whoCan{
			client: client,
		}
		// when
		err := wc.validateNamespace("nonexistent")
		// then
		assert.EqualError(t, err, "not found")
	})

	t.Run("Should return error when namespace is not active", func(t *testing.T) {
		// given
		client := fake.NewSimpleClientset()
		// and
		client.Fake.PrependReactor("get", "namespaces", func(action clientTesting.Action) (bool, runtime.Object, error) {
			obj := &v1.Namespace{
				Status: v1.NamespaceStatus{
					Phase: v1.NamespaceTerminating,
				},
			}
			return true, obj, nil
		})
		// and
		wc := whoCan{
			client: client,
		}
		// when
		err := wc.validateNamespace("foo")
		// then
		assert.EqualError(t, err, "invalid status: Terminating")
	})

	t.Run("Should return nil when namespace is active", func(t *testing.T) {
		// given
		client := fake.NewSimpleClientset()
		// and
		client.Fake.PrependReactor("get", "namespaces", func(action clientTesting.Action) (bool, runtime.Object, error) {
			obj := &v1.Namespace{
				Status: v1.NamespaceStatus{
					Phase: v1.NamespaceActive,
				},
			}
			return true, obj, nil
		})
		// and
		wc := whoCan{
			client: client,
		}
		// when
		err := wc.validateNamespace("foo")
		// then
		assert.NoError(t, err)
	})

}
