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
	"k8s.io/apimachinery/pkg/runtime/schema"
	clioptions "k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes/fake"
	clientTesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/clientcmd"
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

func (r *resourceResolverMock) Resolve(verb, resource, subResource string) (schema.GroupResource, error) {
	args := r.Called(verb, resource, subResource)
	return args.Get(0).(schema.GroupResource), args.Error(1)
}

type clientConfigMock struct {
	mock.Mock
	clientcmd.DirectClientConfig
}

func (cc *clientConfigMock) Namespace() (string, bool, error) {
	args := cc.Called()
	return args.String(0), args.Bool(1), args.Error(2)
}

type policyRuleMatcherMock struct {
	mock.Mock
}

func (prm *policyRuleMatcherMock) Matches(rule rbac.PolicyRule, action Action) bool {
	args := prm.Called(rule, action)
	return args.Bool(0)
}

func (prm *policyRuleMatcherMock) MatchesRole(role rbac.Role, action Action) bool {
	args := prm.Called(role, action)
	return args.Bool(0)
}

func (prm *policyRuleMatcherMock) MatchesClusterRole(role rbac.ClusterRole, action Action) bool {
	args := prm.Called(role, action)
	return args.Bool(0)
}

func TestComplete(t *testing.T) {

	type currentContext struct {
		namespace string
		err       error
	}

	type flags struct {
		namespace     string
		allNamespaces bool
	}

	type resolution struct {
		verb        string
		resource    string
		subResource string

		gr  schema.GroupResource
		err error
	}

	type expected struct {
		namespace    string
		verb         string
		resource     string
		resourceName string
		err          error
	}

	data := []struct {
		scenario string

		currentContext *currentContext

		flags      flags
		args       []string
		resolution *resolution

		expected expected
	}{
		{
			scenario:       "A",
			currentContext: &currentContext{namespace: "foo"},
			flags:          flags{namespace: "", allNamespaces: false},
			args:           []string{"list", "pods"},
			resolution:     &resolution{verb: "list", resource: "pods", gr: schema.GroupResource{Resource: "pods"}},
			expected: expected{
				namespace:    "foo",
				verb:         "list",
				resource:     "pods",
				resourceName: "",
			},
		},
		{
			scenario:       "B",
			currentContext: &currentContext{err: errors.New("cannot open context")},
			flags:          flags{namespace: "", allNamespaces: false},
			args:           []string{"list", "pods"},
			resolution:     &resolution{verb: "list", resource: "pods", gr: schema.GroupResource{Resource: "pods"}},
			expected: expected{
				namespace:    "",
				verb:         "list",
				resource:     "pods",
				resourceName: "",
				err:          errors.New("getting namespace from current context: cannot open context"),
			},
		},
		{
			scenario:   "C",
			flags:      flags{namespace: "", allNamespaces: true},
			args:       []string{"get", "service/mongodb"},
			resolution: &resolution{verb: "get", resource: "service", gr: schema.GroupResource{Resource: "services"}},
			expected: expected{
				namespace:    core.NamespaceAll,
				verb:         "get",
				resource:     "services",
				resourceName: "mongodb",
			},
		},
		{
			scenario:   "D",
			flags:      flags{namespace: "bar", allNamespaces: false},
			args:       []string{"delete", "pv"},
			resolution: &resolution{verb: "delete", resource: "pv", gr: schema.GroupResource{Resource: "persistentvolumes"}},
			expected: expected{
				namespace: "bar",
				verb:      "delete",
				resource:  "persistentvolumes",
			},
		},
		{
			scenario:   "E",
			flags:      flags{allNamespaces: false},
			args:       []string{"delete", "pv"},
			resolution: &resolution{verb: "delete", resource: "pv", err: errors.New("failed")},
			expected: expected{
				namespace: "",
				verb:      "delete",
				err:       errors.New("resolving resource: failed"),
				resource:  "",
			},
		},
		{
			scenario: "F",
			flags:    flags{namespace: "foo"},
			args:     []string{"get", "/logs"},
			expected: expected{
				namespace: "foo",
				verb:      "get",
				resource:  "",
			},
		},
		{
			scenario: "G",
			args:     []string{},
			expected: expected{
				err: errors.New("you must specify two or three arguments: verb, resource, and optional resourceName"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.scenario, func(t *testing.T) {
			// setup
			configFlags := &clioptions.ConfigFlags{
				Namespace: &tt.flags.namespace,
			}

			kubeClient := fake.NewSimpleClientset()
			clientConfig := new(clientConfigMock)
			namespaceValidator := new(namespaceValidatorMock)
			accessChecker := new(accessCheckerMock)
			resourceResolver := new(resourceResolverMock)
			policyRuleMatcher := new(policyRuleMatcherMock)

			if tt.resolution != nil {
				resourceResolver.On("Resolve", tt.resolution.verb, tt.resolution.resource, tt.resolution.subResource).
					Return(tt.resolution.gr, tt.resolution.err)
			}
			if tt.currentContext != nil {
				clientConfig.On("Namespace").Return(tt.currentContext.namespace, false, tt.currentContext.err)
			}

			// given
			o := whoCan{
				Action: Action{
					namespace:     tt.flags.namespace,
					allNamespaces: tt.flags.allNamespaces,
				},
				configFlags:        configFlags,
				clientConfig:       clientConfig,
				clientNamespace:    kubeClient.CoreV1().Namespaces(),
				clientRBAC:         kubeClient.RbacV1(),
				namespaceValidator: namespaceValidator,
				resourceResolver:   resourceResolver,
				accessChecker:      accessChecker,
				policyRuleMatcher:  policyRuleMatcher,
				IOStreams:          clioptions.NewTestIOStreamsDiscard(),
			}

			// when
			err := o.Complete(tt.args)

			// then
			assert.Equal(t, tt.expected.err, err)
			assert.Equal(t, tt.expected.namespace, o.namespace)
			assert.Equal(t, tt.expected.verb, o.verb)
			assert.Equal(t, tt.expected.resource, o.gr.Resource)
			assert.Equal(t, tt.expected.resourceName, o.resourceName)

			clientConfig.AssertExpectations(t)
			resourceResolver.AssertExpectations(t)
		})

	}

}

func TestValidate(t *testing.T) {
	type namespaceValidation struct {
		returnedError error
	}

	data := []struct {
		scenario string

		nonResourceURL string
		subResource    string
		namespace      string

		*namespaceValidation

		expectedErr error
	}{
		{
			scenario:            "Should return nil when namespace is valid",
			namespace:           "foo",
			namespaceValidation: &namespaceValidation{returnedError: nil},
		},
		{
			scenario:            "Should return error when namespace does not exist",
			namespace:           "bar",
			namespaceValidation: &namespaceValidation{returnedError: errors.New("\"bar\" not found")},
			expectedErr:         errors.New("validating namespace: \"bar\" not found"),
		},
		{
			scenario:       "Should return error when --subresource flag is used with non-resource URL",
			nonResourceURL: "/api",
			subResource:    "logs",
			expectedErr:    errors.New("--subresource cannot be used with NONRESOURCEURL"),
		},
	}

	for _, tt := range data {
		t.Run(tt.scenario, func(t *testing.T) {
			// given
			namespaceValidator := new(namespaceValidatorMock)
			if tt.namespaceValidation != nil {
				namespaceValidator.On("Validate", tt.namespace).
					Return(tt.namespaceValidation.returnedError)
			}

			o := &whoCan{
				Action: Action{
					nonResourceURL: tt.nonResourceURL,
					subResource:    tt.subResource,
					namespace:      tt.namespace,
				},
				namespaceValidator: namespaceValidator,
			}

			// when
			err := o.Validate()

			// then
			assert.Equal(t, tt.expectedErr, err)
			namespaceValidator.AssertExpectations(t)
		})
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
			policyRuleMatcher := new(policyRuleMatcherMock)
			for _, prm := range tt.permissions {
				accessChecker.On("IsAllowedTo", prm.verb, prm.resource, prm.namespace).
					Return(prm.allowed, nil)
			}

			// given
			configFlags := &clioptions.ConfigFlags{}
			wc := whoCan{
				Action: Action{
					namespace: tt.namespace,
				},
				configFlags:        configFlags,
				clientConfig:       configFlags.ToRawKubeConfigLoader(),
				clientNamespace:    client.CoreV1().Namespaces(),
				clientRBAC:         client.RbacV1(),
				namespaceValidator: namespaceValidator,
				resourceResolver:   resourceResolver,
				accessChecker:      accessChecker,
				policyRuleMatcher:  policyRuleMatcher,
				IOStreams:          clioptions.NewTestIOStreamsDiscard(),
			}

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

func TestWhoCan_GetRolesFor(t *testing.T) {
	// given
	policyRuleMatcher := new(policyRuleMatcherMock)
	client := fake.NewSimpleClientset()

	action := Action{verb: "list", resource: "services"}

	viewServicesRole := rbac.Role{
		ObjectMeta: meta.ObjectMeta{
			Name: "view-services",
		},
		Rules: []rbac.PolicyRule{
			{
				Verbs:     []string{"get", "list"},
				Resources: []string{"services"},
			},
		},
	}

	viewPodsRole := rbac.Role{
		ObjectMeta: meta.ObjectMeta{
			Name: "view-pods",
		},
		Rules: []rbac.PolicyRule{
			{
				Verbs:     []string{"get", "list"},
				Resources: []string{"services"},
			},
		},
	}

	client.Fake.PrependReactor("list", "roles", func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
		list := &rbac.RoleList{
			Items: []rbac.Role{
				viewServicesRole,
				viewPodsRole,
			},
		}

		return true, list, nil
	})

	policyRuleMatcher.On("MatchesRole", viewServicesRole, action).Return(true)
	policyRuleMatcher.On("MatchesRole", viewPodsRole, action).Return(false)

	wc := whoCan{
		clientRBAC:        client.RbacV1(),
		policyRuleMatcher: policyRuleMatcher,
	}

	// when
	names, err := wc.GetRolesFor(action)

	// then
	require.NoError(t, err)
	assert.EqualValues(t, map[string]struct{}{"view-services": {}}, names)
	policyRuleMatcher.AssertExpectations(t)
}

func TestWhoCan_GetClusterRolesFor(t *testing.T) {
	// given
	policyRuleMatcher := new(policyRuleMatcherMock)
	client := fake.NewSimpleClientset()

	action := Action{verb: "get", resource: "/logs"}

	getLogsRole := rbac.ClusterRole{
		ObjectMeta: meta.ObjectMeta{
			Name: "get-logs",
		},
		Rules: []rbac.PolicyRule{
			{
				Verbs:           []string{"get"},
				NonResourceURLs: []string{"/logs"},
			},
		},
	}

	getApiRole := rbac.ClusterRole{
		ObjectMeta: meta.ObjectMeta{
			Name: "get-api",
		},
		Rules: []rbac.PolicyRule{
			{
				Verbs:           []string{"get"},
				NonResourceURLs: []string{"/api"},
			},
		},
	}

	client.Fake.PrependReactor("list", "clusterroles", func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
		list := &rbac.ClusterRoleList{
			Items: []rbac.ClusterRole{
				getLogsRole,
				getApiRole,
			},
		}

		return true, list, nil
	})

	policyRuleMatcher.On("MatchesClusterRole", getLogsRole, action).Return(false)
	policyRuleMatcher.On("MatchesClusterRole", getApiRole, action).Return(true)

	wc := whoCan{
		clientRBAC:        client.RbacV1(),
		policyRuleMatcher: policyRuleMatcher,
	}

	// when
	names, err := wc.GetClusterRolesFor(action)

	// then
	require.NoError(t, err)
	assert.EqualValues(t, map[string]struct{}{"get-api": {}}, names)
	policyRuleMatcher.AssertExpectations(t)
}

func TestWhoCan_GetRoleBindings(t *testing.T) {
	client := fake.NewSimpleClientset()

	namespace := "foo"
	roleNames := map[string]struct{}{"view-pods": {}}
	clusterRoleNames := map[string]struct{}{"view-configmaps": {}}

	viewPodsBnd := rbac.RoleBinding{
		ObjectMeta: meta.ObjectMeta{
			Name:      "view-pods-bnd",
			Namespace: namespace,
		},
		RoleRef: rbac.RoleRef{
			Kind: "Role",
			Name: "view-pods",
		},
	}

	viewConfigMapsBnd := rbac.RoleBinding{
		ObjectMeta: meta.ObjectMeta{
			Name: "view-configmaps-bnd",
		},
		RoleRef: rbac.RoleRef{
			Kind: "ClusterRole",
			Name: "view-configmaps",
		},
	}

	client.Fake.PrependReactor("list", "rolebindings", func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
		list := &rbac.RoleBindingList{
			Items: []rbac.RoleBinding{
				viewPodsBnd,
				viewConfigMapsBnd,
			},
		}

		return true, list, nil
	})

	wc := whoCan{
		clientRBAC: client.RbacV1(),
		Action:     Action{namespace: namespace},
	}

	// when
	bindings, err := wc.GetRoleBindings(roleNames, clusterRoleNames)

	// then
	require.NoError(t, err)
	assert.Equal(t, 2, len(bindings))
	assert.Contains(t, bindings, viewPodsBnd)
	assert.Contains(t, bindings, viewConfigMapsBnd)
}

func TestWhoCan_GetClusterRoleBindings(t *testing.T) {
	client := fake.NewSimpleClientset()

	clusterRoleNames := map[string]struct{}{"get-healthz": {}}

	getLogsBnd := rbac.ClusterRoleBinding{
		ObjectMeta: meta.ObjectMeta{
			Name: "get-logs-bnd",
		},
		RoleRef: rbac.RoleRef{
			Kind: "ClusterRoleBinding",
			Name: "get-logs",
		},
	}

	getHealthzBnd := rbac.ClusterRoleBinding{
		ObjectMeta: meta.ObjectMeta{
			Name: "get-healthz-bnd",
		},
		RoleRef: rbac.RoleRef{
			Kind: "ClusterRoleBinding",
			Name: "get-healthz",
		},
	}

	client.Fake.PrependReactor("list", "clusterrolebindings", func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
		list := &rbac.ClusterRoleBindingList{
			Items: []rbac.ClusterRoleBinding{
				getLogsBnd,
				getHealthzBnd,
			},
		}

		return true, list, nil
	})

	wc := whoCan{
		clientRBAC: client.RbacV1(),
	}

	// when
	bindings, err := wc.GetClusterRoleBindings(clusterRoleNames)

	// then
	require.NoError(t, err)
	assert.Equal(t, 1, len(bindings))
	assert.Contains(t, bindings, getHealthzBnd)
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
				Action: Action{
					verb:           tt.verb,
					resource:       tt.resource,
					nonResourceURL: tt.nonResourceURL,
					resourceName:   tt.resourceName,
				},
				IOStreams: streams,
			}

			// when
			wc.output(tt.roleBindings, tt.clusterRoleBindings)

			// then
			assert.Equal(t, tt.output, out.String())
		})

	}

}
