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

func TestWhoCan_validateNamespace(t *testing.T) {

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

func TestWhoCan_policyMatches(t *testing.T) {

	data := []struct {
		name string

		verb         string
		resource     string
		resourceName string

		rule rbacv1.PolicyRule

		matches bool
	}{
		{
			name: "scenario1",
			verb: "get", resource: "service", resourceName: "",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get", "list"},
				Resources: []string{"service"},
			},
			matches: true,
		},
		{
			name: "scenario2",
			verb: "get", resource: "service", resourceName: "",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get", "list"},
				Resources: []string{"*"},
			},
			matches: true,
		},
		{
			name: "scenario3",
			verb: "get", resource: "service", resourceName: "",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"*"},
				Resources: []string{"service"},
			},
			matches: true,
		},
		{
			name: "scenario4",
			verb: "get", resource: "service", resourceName: "mongodb",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get", "list"},
				Resources: []string{"service"},
			},
			matches: true,
		},
		{
			name: "scenario5",
			verb: "get", resource: "service", resourceName: "mongodb",
			rule: rbacv1.PolicyRule{
				Verbs:         []string{"get", "list"},
				Resources:     []string{"service"},
				ResourceNames: []string{"mongodb", "nginx"},
			},
			matches: true,
		},
		{
			name: "scenario6",
			verb: "get", resource: "service", resourceName: "mongodb",
			rule: rbacv1.PolicyRule{
				Verbs:         []string{"get", "list"},
				Resources:     []string{"service"},
				ResourceNames: []string{"nginx"},
			},
			matches: false,
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {

			wc := whoCan{
				verb:         tt.verb,
				resource:     tt.resource,
				resourceName: tt.resourceName,
			}
			matches := wc.policyRuleMatches(tt.rule)

			assert.Equal(t, tt.matches, matches)
		})
	}

}
