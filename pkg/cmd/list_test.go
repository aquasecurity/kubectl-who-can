package cmd

import (
	"bytes"
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clioptions "k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes/fake"
	clientTesting "k8s.io/client-go/testing"
	"testing"

	rbac "k8s.io/api/rbac/v1"
)

type accessCheckerMock struct {
	mock.Mock
}

func (m *accessCheckerMock) IsAllowedTo(verb, resource, namespace string) (bool, error) {
	args := m.Called(verb, resource, namespace)
	return args.Bool(0), args.Error(1)
}

type namespaceValidatorMock struct {
	mock.Mock
}

func (w *namespaceValidatorMock) Validate(name string) error {
	args := w.Called(name)
	return args.Error(0)
}

type resourceResolverMock struct {
	mock.Mock
}

func (r *resourceResolverMock) Resolve(verb, resource, subResource string) (string, error) {
	args := r.Called(verb, resource, subResource)
	return args.String(0), args.Error(1)
}

func TestComplete(t *testing.T) {

	type kubeContext struct {
		namespace string
	}

	type flags struct {
		namespace     string
		allNamespaces bool
	}

	type resolution struct {
		verb        string
		resource    string
		subResource string
		result      string
	}

	type expected struct {
		namespace    string
		verb         string
		resource     string
		resourceName string
	}

	data := []struct {
		scenario string

		kubeContext

		flags      flags
		args       []string
		resolution resolution

		expected
	}{
		{
			scenario:    "A",
			kubeContext: kubeContext{namespace: ""},
			flags:       flags{namespace: "", allNamespaces: false},
			args:        []string{"list", "pods"},
			resolution:  resolution{verb: "list", resource: "pods", result: "pods"},
			expected: expected{
				namespace:    "default",
				verb:         "list",
				resource:     "pods",
				resourceName: "",
			},
		},
		{
			scenario:    "B",
			kubeContext: kubeContext{namespace: ""},
			flags:       flags{namespace: "", allNamespaces: true},
			args:        []string{"get", "service/mongodb"},
			resolution:  resolution{verb: "get", resource: "service", result: "services"},
			expected: expected{
				namespace:    core.NamespaceAll,
				verb:         "get",
				resource:     "services",
				resourceName: "mongodb",
			},
		},
		{
			scenario:    "C",
			kubeContext: kubeContext{namespace: "foo"},
			flags:       flags{namespace: "", allNamespaces: false},
			args:        []string{"create", "cm"},
			resolution:  resolution{verb: "create", resource: "cm", result: "configmaps"},
			expected: expected{
				namespace: "foo",
				verb:      "create",
				resource:  "configmaps",
			},
		},
		{
			scenario:    "D",
			kubeContext: kubeContext{namespace: "foo"},
			flags:       flags{namespace: "bar", allNamespaces: false},
			args:        []string{"delete", "pv"},
			resolution:  resolution{verb: "delete", resource: "pv", result: "persistentvolumes"},
			expected: expected{
				namespace: "bar",
				verb:      "delete",
				resource:  "persistentvolumes",
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.scenario, func(t *testing.T) {
			// setup
			configFlags := clioptions.ConfigFlags{Namespace: &tt.kubeContext.namespace}

			kubeClient := fake.NewSimpleClientset()
			namespaceValidator := new(namespaceValidatorMock)
			accessChecker := new(accessCheckerMock)
			resourceResolver := new(resourceResolverMock)

			resourceResolver.On("Resolve", tt.resolution.verb, tt.resolution.resource, tt.resolution.subResource).
				Return(tt.resolution.result, nil)

			// given
			o := NewWhoCanOptions(configFlags.ToRawKubeConfigLoader(),
				kubeClient.CoreV1().Namespaces(),
				kubeClient.RbacV1(),
				namespaceValidator,
				resourceResolver,
				accessChecker,
				clioptions.NewTestIOStreamsDiscard())

			// and
			o.namespace = tt.flags.namespace
			o.allNamespaces = tt.flags.allNamespaces

			// when
			err := o.Complete(tt.args)

			// then
			require.NoError(t, err)
			assert.Equal(t, tt.expected.namespace, o.namespace)
			assert.Equal(t, tt.expected.verb, o.verb)
			assert.Equal(t, tt.expected.resource, o.resource)
			assert.Equal(t, tt.expected.resourceName, o.resourceName)

			resourceResolver.AssertExpectations(t)
		})

	}

}

func TestValidate(t *testing.T) {
	data := []struct {
		scenario      string
		namespace     string
		validationErr error
		expectedErr   error
	}{
		{
			scenario:  "Should return nil when namespace is valid",
			namespace: "foo",
		},
		{
			scenario:      "Should return error when namespace does not exist",
			namespace:     "bar",
			validationErr: errors.New("\"bar\" not found"),
			expectedErr:   errors.New("validating namespace: \"bar\" not found"),
		},
	}

	for _, tt := range data {
		t.Run(tt.scenario, func(t *testing.T) {
			// given
			namespaceValidator := new(namespaceValidatorMock)
			namespaceValidator.On("Validate", tt.namespace).Return(tt.validationErr)

			o := &whoCan{}
			o.namespace = tt.namespace
			o.namespaceValidator = namespaceValidator

			// when
			err := o.Validate()

			// then
			assert.Equal(t, tt.expectedErr, err)
			namespaceValidator.AssertExpectations(t)
		})
	}
}

func TestMatch(t *testing.T) {
	r := make(roles, 1)
	entry := role{
		name:          "hello",
		isClusterRole: false,
	}
	r[entry] = struct{}{}

	rr := rbac.RoleRef{
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
		list := &core.NamespaceList{
			Items: []core.Namespace{
				{
					ObjectMeta: meta.ObjectMeta{Name: FooNs},
				},
				{
					ObjectMeta: meta.ObjectMeta{Name: BarNs},
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
			namespace: core.NamespaceAll,
			permissions: []permission{
				// Permissions to list all namespaces
				{verb: "list", resource: "namespaces", namespace: core.NamespaceAll, allowed: false},
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
			// setup
			namespaceValidator := new(namespaceValidatorMock)
			resourceResolver := new(resourceResolverMock)
			accessChecker := new(accessCheckerMock)
			for _, prm := range tt.permissions {
				accessChecker.On("IsAllowedTo", prm.verb, prm.resource, prm.namespace).
					Return(prm.allowed, nil)
			}

			// given
			configFlags := clioptions.ConfigFlags{}
			wc := NewWhoCanOptions(configFlags.ToRawKubeConfigLoader(),
				client.CoreV1().Namespaces(),
				client.RbacV1(),
				namespaceValidator,
				resourceResolver,
				accessChecker,
				clioptions.NewTestIOStreamsDiscard())
			wc.namespace = tt.namespace

			// when
			warnings, err := wc.checkAPIAccess()

			// then
			assert.Equal(t, tt.expectedError, err)
			assert.Equal(t, tt.expectedWarnings, warnings)

			accessChecker.AssertExpectations(t)
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
			wc.Out = &buf
			wc.printAPIAccessWarnings(tt.warnings)
			assert.Equal(t, tt.expectedOutput, buf.String())
		})
	}
}

func TestWhoCan_policyRuleMatches(t *testing.T) {

	data := []struct {
		scenario string

		verb           string
		resource       string
		resourceName   string
		nonResourceURL string

		rule rbac.PolicyRule

		matches bool
	}{
		{
			scenario: "A",
			verb:     "get", resource: "services", resourceName: "",
			rule: rbac.PolicyRule{
				Verbs:     []string{"get", "list"},
				Resources: []string{"services"},
			},
			matches: true,
		},
		{
			scenario: "B",
			verb:     "get", resource: "services", resourceName: "",
			rule: rbac.PolicyRule{
				Verbs:     []string{"get", "list"},
				Resources: []string{"*"},
			},
			matches: true,
		},
		{
			scenario: "C",
			verb:     "get", resource: "services", resourceName: "",
			rule: rbac.PolicyRule{
				Verbs:     []string{"*"},
				Resources: []string{"services"},
			},
			matches: true,
		},
		{
			scenario: "D",
			verb:     "get", resource: "services", resourceName: "mongodb",
			rule: rbac.PolicyRule{
				Verbs:     []string{"get", "list"},
				Resources: []string{"services"},
			},
			matches: true,
		},
		{
			scenario: "E",
			verb:     "get", resource: "services", resourceName: "mongodb",
			rule: rbac.PolicyRule{
				Verbs:         []string{"get", "list"},
				Resources:     []string{"services"},
				ResourceNames: []string{"mongodb", "nginx"},
			},
			matches: true,
		},
		{
			scenario: "F",
			verb:     "get", resource: "services", resourceName: "mongodb",
			rule: rbac.PolicyRule{
				Verbs:         []string{"get", "list"},
				Resources:     []string{"services"},
				ResourceNames: []string{"nginx"},
			},
			matches: false,
		},
		{
			scenario: "G",
			verb:     "get", resource: "services", resourceName: "",
			rule: rbac.PolicyRule{
				Verbs:         []string{"get", "list"},
				Resources:     []string{"services"},
				ResourceNames: []string{"nginx"},
			},
			matches: false,
		},
		{
			scenario: "H",
			verb:     "get", resource: "pods", resourceName: "",
			rule: rbac.PolicyRule{
				Verbs:     []string{"create"},
				Resources: []string{"pods"},
			},
			matches: false,
		},
		{
			scenario: "I",
			verb:     "get", resource: "persistentvolumes", resourceName: "",
			rule: rbac.PolicyRule{
				Verbs:     []string{"get"},
				Resources: []string{"pods"},
			},
			matches: false,
		},
		{
			scenario: "J",
			verb:     "get", nonResourceURL: "/logs",
			rule: rbac.PolicyRule{
				Verbs:           []string{"get"},
				NonResourceURLs: []string{"/logs"},
			},
			matches: true,
		},
		{
			scenario: "K",
			verb:     "get", nonResourceURL: "/logs",
			rule: rbac.PolicyRule{
				Verbs:           []string{"post"},
				NonResourceURLs: []string{"/logs"},
			},
			matches: false,
		},
		{
			scenario: "L",
			verb:     "get", nonResourceURL: "/logs",
			rule: rbac.PolicyRule{
				Verbs:           []string{"get"},
				NonResourceURLs: []string{"/api"},
			},
			matches: false,
		},
	}

	for _, tt := range data {
		t.Run(tt.scenario, func(t *testing.T) {

			wc := whoCan{
				verb:           tt.verb,
				resource:       tt.resource,
				resourceName:   tt.resourceName,
				nonResourceURL: tt.nonResourceURL,
			}
			matches := wc.policyRuleMatches(tt.rule)

			assert.Equal(t, tt.matches, matches)
		})
	}

}

func TestWhoCan_output(t *testing.T) {
	data := []struct {
		scenario string

		verb           string
		resource       string
		nonResourceURL string
		resourceName   string

		roleBindings        []rbac.RoleBinding
		clusterRoleBindings []rbac.ClusterRoleBinding

		output string
	}{
		{
			scenario: "A",
			verb:     "get", resource: "pods", resourceName: "",
			output: `No subjects found with permissions to get pods assigned through RoleBindings

No subjects found with permissions to get pods assigned through ClusterRoleBindings
`,
		},
		{
			scenario: "B",
			verb:     "get", resource: "pods", resourceName: "my-pod",
			output: `No subjects found with permissions to get pods/my-pod assigned through RoleBindings

No subjects found with permissions to get pods/my-pod assigned through ClusterRoleBindings
`,
		},
		{
			scenario: "C",
			verb:     "get", nonResourceURL: "/healthz",
			output: "No subjects found with permissions to get /healthz assigned through ClusterRoleBindings\n",
		},
		{
			scenario: "D",
			verb:     "get", resource: "pods",
			roleBindings: []rbac.RoleBinding{
				{
					ObjectMeta: meta.ObjectMeta{Name: "Alice-can-view-pods", Namespace: "default"},
					Subjects: []rbac.Subject{
						{Name: "Alice", Kind: "User"},
					}},
				{
					ObjectMeta: meta.ObjectMeta{Name: "Admins-can-view-pods", Namespace: "bar"},
					Subjects: []rbac.Subject{
						{Name: "Admins", Kind: "Group"},
					}},
			},
			clusterRoleBindings: []rbac.ClusterRoleBinding{
				{
					ObjectMeta: meta.ObjectMeta{Name: "Bob-and-Eve-can-view-pods", Namespace: "default"},
					Subjects: []rbac.Subject{
						{Name: "Bob", Kind: "ServiceAccount", Namespace: "foo"},
						{Name: "Eve", Kind: "User"},
					},
				},
			},
			output: `ROLEBINDING           NAMESPACE  SUBJECT  TYPE   SA-NAMESPACE
Alice-can-view-pods   default    Alice    User   
Admins-can-view-pods  bar        Admins   Group  

CLUSTERROLEBINDING         SUBJECT  TYPE            SA-NAMESPACE
Bob-and-Eve-can-view-pods  Bob      ServiceAccount  foo
Bob-and-Eve-can-view-pods  Eve      User            
`,
		},
	}

	for _, tt := range data {
		t.Run(tt.scenario, func(t *testing.T) {
			// given
			streams, _, out, _ := clioptions.NewTestIOStreams()
			wc := whoCan{
				verb:           tt.verb,
				resource:       tt.resource,
				nonResourceURL: tt.nonResourceURL,
				resourceName:   tt.resourceName,

				IOStreams: streams,
			}

			// when
			wc.output(tt.roleBindings, tt.clusterRoleBindings)

			// then
			assert.Equal(t, tt.output, out.String())
		})

	}

}
