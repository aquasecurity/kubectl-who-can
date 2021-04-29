package test

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/aquasecurity/kubectl-who-can/pkg/cmd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	clientext "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	clioptions "k8s.io/cli-runtime/pkg/genericclioptions"
	client "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	// commonLabels is a set of common labels added to each object created by this integration test, which allows us
	// to do a proper cleanup and distinguish them from the default object created on cluster init.
	//
	// kubectl delete ns,crd,role,rolebinding,clusterrole,clusterrolebindings -l app.kubernetes.io/name=who-can
	commonLabels = labels.Set{
		"app.kubernetes.io/name": "who-can",
	}
)

func TestIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Integration test")
	}

	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	require.NoError(t, err)

	coreClient, err := client.NewForConfig(config)
	require.NoError(t, err)

	extClient, err := clientext.NewForConfig(config)
	require.NoError(t, err)

	createCRDs(t, extClient.CustomResourceDefinitions())
	configureRBAC(t, coreClient)

	testCases := []struct {
		name   string
		args   []string
		output []string
	}{
		{
			name: "Should print who can create configmaps",
			args: []string{"create", "cm"},
			output: []string{
				"ROLEBINDING                  NAMESPACE  SUBJECT  TYPE  SA-NAMESPACE",
				"alice-can-create-configmaps  default    Alice    User",
				"rory-can-create-configmaps   default    Rory     User",
			},
		},
		{
			name: "Should print who can get /healthz",
			args: []string{"get", "/logs"},
			output: []string{
				"CLUSTERROLEBINDING  SUBJECT  TYPE  SA-NAMESPACE",
				"bob-can-get-logs    Bob      User"},
		},
		{
			name: "Should print who can list services in the namespace `foo`",
			args: []string{"list", "services", "-n", "foo"},
			output: []string{
				"operator-can-view-services  foo        operator  ServiceAccount  bar",
			},
		},
		{
			name: "Should print who can scale deployments",
			args: []string{"update", "deployment", "--subresource", "scale"},
			output: []string{
				"devops-can-scale-workloads  default    devops   Group",
			},
		},
		{
			name: "Should print who can get pod named `pod-xyz` in the namespace `foo`",
			args: []string{"get", "pods/pod-xyz", "--namespace=foo"},
			output: []string{
				"batman-can-view-pod-xyz  foo        Batman   User",
			},
		},
		{
			name: "Should print who can list pods in group `metrics.k8s.io`",
			args: []string{"list", "pods.metrics.k8s.io"},
			output: []string{
				"spiderman-can-view-pod-metrics               Spiderman                       User",
			},
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {

			streams, _, out, _ := clioptions.NewTestIOStreams()
			root, err := cmd.NewWhoCanCommand(streams)
			require.NoError(t, err)

			root.SetArgs(tt.args)

			err = root.Execute()
			require.NoError(t, err)

			prettyPrintWhoCanOutput(t, tt.args, out)

			for _, line := range tt.output {
				// TODO Improve asserts on the output
				// I believe we can do better with such asserts by leveraging label selectors.
				// By adding the "app.kubernetes.io/name=who-can" label to [Cluster]Roles and
				// [Cluster]RoleBindings created by this integration test, we can distinguish
				// them from the default RBAC settings which are labeled with
				// "kubernetes.io/bootstrapping=rbac-defaults" or do not have labels at all.
				assert.Contains(t, out.String(), line)
			}
		})
	}

}

func prettyPrintWhoCanOutput(t *testing.T, args []string, out *bytes.Buffer) {
	t.Helper()

	if testing.Verbose() {
		t.Logf("\n%s\n%s\n%s%s\n", strings.Repeat("~", 117),
			"$ kubectl who-can "+strings.Join(args, " "),
			out.String(),
			strings.Repeat("~", 117))
	}
}

func createCRDs(t *testing.T, client clientext.CustomResourceDefinitionInterface) {
	t.Helper()
	ctx := context.Background()
	_, err := client.Create(ctx, &apiext.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "pods.metrics.k8s.io",
			Labels: commonLabels,
		},
		Spec: apiext.CustomResourceDefinitionSpec{
			Scope: apiext.NamespaceScoped,
			Group: "metrics.k8s.io",
			Versions: []apiext.CustomResourceDefinitionVersion{
				{
					Name:    "v1beta1",
					Served:  true,
					Storage: true,
				},
			},
			Names: apiext.CustomResourceDefinitionNames{
				Kind:       "PodMetrics",
				Singular:   "pod",
				Plural:     "pods",
				ShortNames: []string{"po"},
			},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
}

func configureRBAC(t *testing.T, coreClient client.Interface) {
	t.Helper()
	ctx := context.Background()
	clientRBAC := coreClient.RbacV1()

	const namespaceFoo = "foo"

	// Define ClusterRoles and ClusterRoleBindings
	_, err := clientRBAC.ClusterRoles().Create(ctx, &rbac.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "create-configmaps",
			Labels: commonLabels,
		},
		Rules: []rbac.PolicyRule{
			{
				APIGroups: []string{""},
				Verbs:     []string{"create"},
				Resources: []string{"configmaps"},
			},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = clientRBAC.ClusterRoles().Create(ctx, &rbac.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "get-logs",
			Labels: commonLabels,
		},
		Rules: []rbac.PolicyRule{
			{
				Verbs:           []string{"get"},
				NonResourceURLs: []string{"/logs"},
			},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = clientRBAC.ClusterRoles().Create(ctx, &rbac.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "view-pod-metrics",
			Labels: commonLabels,
		},
		Rules: []rbac.PolicyRule{
			{
				Verbs:     []string{"get", "list"},
				APIGroups: []string{"metrics.k8s.io"},
				Resources: []string{"pods"},
			},
		},
	}, metav1.CreateOptions{})

	_, err = clientRBAC.ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "bob-can-get-logs",
			Labels: commonLabels,
		},
		RoleRef: rbac.RoleRef{
			Name: "get-logs",
			Kind: cmd.ClusterRoleKind,
		},
		Subjects: []rbac.Subject{
			{
				Kind: rbac.UserKind,
				Name: "Bob",
			},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = clientRBAC.ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "spiderman-can-view-pod-metrics",
			Labels: commonLabels,
		},
		RoleRef: rbac.RoleRef{
			Name: "view-pod-metrics",
			Kind: cmd.ClusterRoleKind,
		},
		Subjects: []rbac.Subject{
			{
				Kind: rbac.UserKind,
				Name: "Spiderman",
			},
		},
	}, metav1.CreateOptions{})

	// Define Roles and RoleBindings
	_, err = clientRBAC.Roles(core.NamespaceDefault).Create(ctx, &rbac.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "create-configmaps",
			Labels: commonLabels,
		},
		Rules: []rbac.PolicyRule{
			{
				APIGroups: []string{""},
				Verbs:     []string{"create"},
				Resources: []string{"configmaps"},
			},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = clientRBAC.RoleBindings(core.NamespaceDefault).Create(ctx, &rbac.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "alice-can-create-configmaps",
			Labels: commonLabels,
		},
		RoleRef: rbac.RoleRef{
			Name: "create-configmaps",
			Kind: cmd.RoleKind,
		},
		Subjects: []rbac.Subject{
			{
				Kind: rbac.UserKind,
				Name: "Alice",
			},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = clientRBAC.RoleBindings(core.NamespaceDefault).Create(ctx, &rbac.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "rory-can-create-configmaps",
			Labels: commonLabels,
		},
		RoleRef: rbac.RoleRef{
			Name: "create-configmaps",
			Kind: cmd.ClusterRoleKind,
		},
		Subjects: []rbac.Subject{
			{
				Kind: rbac.UserKind,
				Name: "Rory",
			},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = clientRBAC.Roles(core.NamespaceDefault).Create(ctx, &rbac.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "scale-workloads",
			Labels: commonLabels,
		},
		Rules: []rbac.PolicyRule{
			{
				APIGroups: []string{"apps"}, // TODO For old clusters it's extensions, newer are apps
				Verbs:     []string{"update"},
				Resources: []string{"deployments/scale"},
			},
		},
	}, metav1.CreateOptions{})

	_, err = clientRBAC.RoleBindings(core.NamespaceDefault).Create(ctx, &rbac.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "devops-can-scale-workloads",
			Labels: commonLabels,
		},
		RoleRef: rbac.RoleRef{
			Name: "scale-workloads",
			Kind: cmd.RoleKind,
		},
		Subjects: []rbac.Subject{
			{
				Kind: rbac.GroupKind,
				Name: "devops",
			},
		},
	}, metav1.CreateOptions{})

	// Configure foo namespace
	_, err = coreClient.CoreV1().Namespaces().Create(ctx, &core.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   namespaceFoo,
			Labels: commonLabels,
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = clientRBAC.Roles(namespaceFoo).Create(ctx, &rbac.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "view-services",
			Labels: commonLabels,
		},
		Rules: []rbac.PolicyRule{
			{
				APIGroups: []string{""},
				Verbs:     []string{"get", "list"},
				Resources: []string{"services"},
			},
			{
				APIGroups: []string{""},
				Verbs:     []string{"get", "list"},
				Resources: []string{"endpoints"},
			},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = clientRBAC.Roles(namespaceFoo).Create(ctx, &rbac.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "view-pod-xyz",
			Labels: commonLabels,
		},
		Rules: []rbac.PolicyRule{
			{
				APIGroups:     []string{""},
				Verbs:         []string{"get"},
				Resources:     []string{"pods"},
				ResourceNames: []string{"pod-xyz"},
			},
		},
	}, metav1.CreateOptions{})

	_, err = clientRBAC.RoleBindings(namespaceFoo).Create(ctx, &rbac.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "operator-can-view-services",
			Labels: commonLabels,
		},
		RoleRef: rbac.RoleRef{
			Name: "view-services",
			Kind: cmd.RoleKind,
		},
		Subjects: []rbac.Subject{
			{
				Kind:      rbac.ServiceAccountKind,
				Name:      "operator",
				Namespace: "bar",
			},
		},
	}, metav1.CreateOptions{})

	_, err = clientRBAC.RoleBindings(namespaceFoo).Create(ctx, &rbac.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "batman-can-view-pod-xyz",
			Labels: commonLabels,
		},
		RoleRef: rbac.RoleRef{
			Name: "view-pod-xyz",
			Kind: cmd.RoleKind,
		},
		Subjects: []rbac.Subject{
			{
				Kind: rbac.UserKind,
				Name: "Batman",
			},
		},
	}, metav1.CreateOptions{})

}
