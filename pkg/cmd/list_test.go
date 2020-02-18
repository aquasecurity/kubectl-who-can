package cmd

import (
	"bytes"
	"errors"
	"github.com/spf13/pflag"
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

func (prm *policyRuleMatcherMock) MatchesRole(role rbac.Role, action resolvedAction) bool {
	args := prm.Called(role, action)
	return args.Bool(0)
}

func (prm *policyRuleMatcherMock) MatchesClusterRole(role rbac.ClusterRole, action resolvedAction) bool {
	args := prm.Called(role, action)
	return args.Bool(0)
}

func TestActionFrom(t *testing.T) {

	type currentContext struct {
		namespace string
		err       error
	}

	type flags struct {
		subResource   string
		namespace     string
		allNamespaces bool
	}

	testCases := []struct {
		name string

		currentContext *currentContext
		flags          flags
		args           []string

		expectedAction Action
		expectedError  error
	}{
		{
			name:           "A",
			currentContext: &currentContext{namespace: "foo"},
			args:           []string{"list", "pods"},
			flags:          flags{namespace: "", allNamespaces: false},
			expectedAction: Action{
				Namespace:    "foo",
				Verb:         "list",
				Resource:     "pods",
				ResourceName: "",
			},
		},
		{
			name:           "B",
			currentContext: &currentContext{err: errors.New("cannot open context")},
			flags:          flags{namespace: "", allNamespaces: false},
			args:           []string{"list", "pods"},
			expectedAction: Action{
				Namespace:    "",
				Verb:         "list",
				Resource:     "pods",
				ResourceName: "",
			},
			expectedError: errors.New("getting namespace from current context: cannot open context"),
		},
		{
			name:  "C",
			flags: flags{namespace: "", allNamespaces: true},
			args:  []string{"get", "service/mongodb"},
			expectedAction: Action{
				AllNamespaces: true,
				Namespace:     core.NamespaceAll,
				Verb:          "get",
				Resource:      "service",
				ResourceName:  "mongodb",
			},
		},
		{
			name:  "D",
			flags: flags{namespace: "bar", allNamespaces: false},
			args:  []string{"delete", "pv"},
			expectedAction: Action{
				Namespace: "bar",
				Verb:      "delete",
				Resource:  "pv",
			},
		},
		{
			name:  "F",
			flags: flags{namespace: "foo"},
			args:  []string{"get", "/logs"},
			expectedAction: Action{
				Namespace:      "foo",
				Verb:           "get",
				NonResourceURL: "/logs",
			},
		},
		{
			name:          "G",
			args:          []string{},
			expectedError: errors.New("you must specify two or three arguments: verb, resource, and optional resourceName"),
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			//setup

			clientConfig := new(clientConfigMock)

			if tt.currentContext != nil {
				clientConfig.On("Namespace").Return(tt.currentContext.namespace, false, tt.currentContext.err)
			}

			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			flags.String(namespaceFlag, tt.flags.namespace, "")
			flags.Bool(allNamespacesFlag, tt.flags.allNamespaces, "")
			flags.String(subResourceFlag, "", "")

			// when
			o, err := ActionFrom(clientConfig, flags, tt.args)

			// then
			assert.Equal(t, tt.expectedError, err)
			assert.Equal(t, tt.expectedAction, o)

			clientConfig.AssertExpectations(t)
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

			o := &WhoCan{
				namespaceValidator: namespaceValidator,
			}

			action := Action{
				NonResourceURL: tt.nonResourceURL,
				SubResource:    tt.subResource,
				Namespace:      tt.namespace,
			}

			// when
			err := o.validate(action)

			// then
			assert.Equal(t, tt.expectedErr, err)
			namespaceValidator.AssertExpectations(t)
		})
	}
}

func TestWhoCan_CheckAPIAccess(t *testing.T) {
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
			wc := WhoCan{
				clientConfig:       configFlags.ToRawKubeConfigLoader(),
				clientNamespace:    client.CoreV1().Namespaces(),
				clientRBAC:         client.RbacV1(),
				namespaceValidator: namespaceValidator,
				resourceResolver:   resourceResolver,
				accessChecker:      accessChecker,
				policyRuleMatcher:  policyRuleMatcher,
			}
			action := Action{
				Namespace: tt.namespace,
			}

			// when
			warnings, err := wc.CheckAPIAccess(action)

			// then
			assert.Equal(t, tt.expectedError, err)
			assert.Equal(t, tt.expectedWarnings, warnings)

			accessChecker.AssertExpectations(t)
		})
	}

}

func TestWhoCan_GetRolesFor(t *testing.T) {
	// given
	policyRuleMatcher := new(policyRuleMatcherMock)
	client := fake.NewSimpleClientset()

	action := resolvedAction{Action: Action{Verb: "list", Resource: "services"}}

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

	wc := WhoCan{
		clientRBAC:        client.RbacV1(),
		policyRuleMatcher: policyRuleMatcher,
	}

	// when
	names, err := wc.getRolesFor(action)

	// then
	require.NoError(t, err)
	assert.EqualValues(t, map[string]struct{}{"view-services": {}}, names)
	policyRuleMatcher.AssertExpectations(t)
}

func TestWhoCan_GetClusterRolesFor(t *testing.T) {
	// given
	policyRuleMatcher := new(policyRuleMatcherMock)
	client := fake.NewSimpleClientset()

	action := resolvedAction{Action: Action{Verb: "get", Resource: "/logs"}}

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

	wc := WhoCan{
		clientRBAC:        client.RbacV1(),
		policyRuleMatcher: policyRuleMatcher,
	}

	// when
	names, err := wc.getClusterRolesFor(action)

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

	wc := WhoCan{
		clientRBAC: client.RbacV1(),
	}
	action := resolvedAction{Action: Action{Namespace: namespace}}

	// when
	bindings, err := wc.getRoleBindings(action, roleNames, clusterRoleNames)

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

	wc := WhoCan{
		clientRBAC: client.RbacV1(),
	}

	// when
	bindings, err := wc.getClusterRoleBindings(clusterRoleNames)

	// then
	require.NoError(t, err)
	assert.Equal(t, 1, len(bindings))
	assert.Contains(t, bindings, getHealthzBnd)
}

func TestPrintWarnings(t *testing.T) {

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
			PrintWarnings(&buf, tt.warnings)
			assert.Equal(t, tt.expectedOutput, buf.String())
		})
	}
}

func TestPrintChecks(t *testing.T) {
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
			var buf bytes.Buffer
			action := Action{
				Verb:           tt.verb,
				Resource:       tt.resource,
				NonResourceURL: tt.nonResourceURL,
				ResourceName:   tt.resourceName,
			}

			// when
			PrintChecks(&buf, action, tt.roleBindings, tt.clusterRoleBindings)

			// then
			assert.Equal(t, tt.output, buf.String())
		})

	}

}
