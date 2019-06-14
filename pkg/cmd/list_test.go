package cmd

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clientTesting "k8s.io/client-go/testing"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
)

type APIAccessCheckerMock struct {
	mock.Mock
}

func (m *APIAccessCheckerMock) IsAllowedTo(verb, resource, namespace string) (bool, error) {
	args := m.Called(verb, resource, namespace)
	return args.Bool(0), args.Error(1)
}

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

func TestWhoCan_checkAPIAccess(t *testing.T) {
	const (
		FooNs = "foo"
		BarNs = "bar"
	)

	type permission struct {
		verb      string
		resource  string
		namespace string
		allowed   bool
	}

	client := fake.NewSimpleClientset()
	client.Fake.PrependReactor("list", "namespaces", func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
		list := &corev1.NamespaceList{
			Items: []corev1.Namespace{
				{
					ObjectMeta: metav1.ObjectMeta{Name: FooNs},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: BarNs},
				},
			},
		}

		return true, list, nil
	})

	data := []struct {
		scenario    string
		namespace   string
		permissions []permission

		expectedWarnings []string
		expectedError    error
	}{
		{
			scenario:  "A",
			namespace: corev1.NamespaceAll,
			permissions: []permission{
				// Permissions to list all namespaces
				{verb: "list", resource: "namespaces", namespace: corev1.NamespaceAll, allowed: false},
				// Permissions in the foo namespace
				{verb: "list", resource: "roles", namespace: FooNs, allowed: true},
				{verb: "list", resource: "rolebindings", namespace: FooNs, allowed: true},
				// Permissions in the bar namespace
				{verb: "list", resource: "roles", namespace: BarNs, allowed: false},
				{verb: "list", resource: "rolebindings", namespace: BarNs, allowed: false},
			},
			expectedWarnings: []string{
				"The user is not allowed to list namespaces",
				"The user is not allowed to list roles in the bar namespace",
				"The user is not allowed to list rolebindings in the bar namespace",
			},
		},
		{
			scenario:  "B",
			namespace: FooNs,
			permissions: []permission{
				// Permissions in the foo namespace
				{verb: "list", resource: "roles", namespace: FooNs, allowed: true},
				{verb: "list", resource: "rolebindings", namespace: FooNs, allowed: false},
			},
			expectedWarnings: []string{
				"The user is not allowed to list rolebindings in the foo namespace",
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.scenario, func(t *testing.T) {
			// given
			checker := new(APIAccessCheckerMock)
			for _, prm := range tt.permissions {
				checker.On("IsAllowedTo", prm.verb, prm.resource, prm.namespace).
					Return(prm.allowed, nil)
			}

			wc := &whoCan{
				namespace:     tt.namespace,
				namespaces:    client.CoreV1().Namespaces(),
				accessChecker: checker,
			}

			// when
			warnings, err := wc.checkAPIAccess()

			// then
			assert.Equal(t, tt.expectedError, err)
			assert.Equal(t, tt.expectedWarnings, warnings)

			checker.AssertExpectations(t)
		})
	}

}

func TestWhoCan_printAPIAccessWarnings(t *testing.T) {

	data := []struct {
		scenario       string
		warnings       []string
		expectedOutput string
	}{
		{
			scenario:       "A",
			warnings:       []string{"w1", "w2"},
			expectedOutput: "Warning: The list might not be complete due to missing permission(s):\n\tw1\n\tw2\n\n",
		},
		{
			scenario:       "B",
			warnings:       []string{},
			expectedOutput: "",
		},
		{
			scenario:       "C",
			warnings:       nil,
			expectedOutput: "",
		},
	}

	for _, tt := range data {
		t.Run(tt.scenario, func(t *testing.T) {
			var buf bytes.Buffer
			wc := whoCan{}
			wc.printAPIAccessWarnings(&buf, tt.warnings)
			assert.Equal(t, tt.expectedOutput, buf.String())
		})
	}
}

func TestWhoCan_policyRuleMatches(t *testing.T) {

	data := []struct {
		scenario string

		verb         string
		resource     string
		resourceName string

		rule rbacv1.PolicyRule

		matches bool
	}{
		{
			scenario: "A",
			verb:     "get", resource: "service", resourceName: "",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get", "list"},
				Resources: []string{"service"},
			},
			matches: true,
		},
		{
			scenario: "B",
			verb:     "get", resource: "service", resourceName: "",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get", "list"},
				Resources: []string{"*"},
			},
			matches: true,
		},
		{
			scenario: "C",
			verb:     "get", resource: "service", resourceName: "",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"*"},
				Resources: []string{"service"},
			},
			matches: true,
		},
		{
			scenario: "D",
			verb:     "get", resource: "service", resourceName: "mongodb",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get", "list"},
				Resources: []string{"service"},
			},
			matches: true,
		},
		{
			scenario: "E",
			verb:     "get", resource: "service", resourceName: "mongodb",
			rule: rbacv1.PolicyRule{
				Verbs:         []string{"get", "list"},
				Resources:     []string{"service"},
				ResourceNames: []string{"mongodb", "nginx"},
			},
			matches: true,
		},
		{
			scenario: "F",
			verb:     "get", resource: "service", resourceName: "mongodb",
			rule: rbacv1.PolicyRule{
				Verbs:         []string{"get", "list"},
				Resources:     []string{"service"},
				ResourceNames: []string{"nginx"},
			},
			matches: false,
		},
		{
			scenario: "G",
			verb:     "get", resource: "service", resourceName: "",
			rule: rbacv1.PolicyRule{
				Verbs:         []string{"get", "list"},
				Resources:     []string{"service"},
				ResourceNames: []string{"nginx"},
			},
			matches: false,
		},
	}

	for _, tt := range data {
		t.Run(tt.scenario, func(t *testing.T) {

			wc := whoCan{
				verb:         tt.verb,
				resource:     tt.resource,
				resourceName: tt.resourceName,

				apiResource: metav1.APIResource{Name: tt.resource},
			}
			matches := wc.policyRuleMatches(tt.rule)

			assert.Equal(t, tt.matches, matches)
		})
	}

}
