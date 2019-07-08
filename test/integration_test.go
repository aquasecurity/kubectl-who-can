package test

import (
	"bytes"
	"github.com/aquasecurity/kubectl-who-can/pkg/cmd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	clientext "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	clioptions "k8s.io/cli-runtime/pkg/genericclioptions"
	client "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"strings"
	"testing"
	"time"
)

func TestIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Integration test")
	}

	// TODO Wait for KUBECONFIG
	time.Sleep(10 * time.Second)

	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	require.NoError(t, err)

	coreClient, err := client.NewForConfig(config)
	require.NoError(t, err)

	extClient, err := clientext.NewForConfig(config)
	require.NoError(t, err)

	createCRDs(t, extClient.CustomResourceDefinitions())
	configureRBAC(t, coreClient)

	data := []struct {
		scenario string
		args     []string
		output   []string
	}{
		{
			scenario: "Should print who can create configmaps",
			args:     []string{"create", "cm"},
			output: []string{
				"ROLEBINDING                  NAMESPACE  SUBJECT  TYPE  SA-NAMESPACE",
				"alice-can-create-configmaps  default    Alice    User",
				"rory-can-create-configmaps   default    Rory     User",
			},
		},
		{
			scenario: "Should print who can get /healthz",
			args:     []string{"get", "/logs"},
			output: []string{
				"CLUSTERROLEBINDING  SUBJECT  TYPE  SA-NAMESPACE",
				"bob-can-get-logs    Bob      User"},
		},
		{
			scenario: "Should print who can list services in the namespace `foo`",
			args:     []string{"list", "services", "-n", "foo"},
			output: []string{
				"operator-can-view-services  foo        operator  ServiceAccount  bar",
			},
		},
		{
			scenario: "Should print who can scale deployments",
			args:     []string{"update", "deployment", "--subresource", "scale"},
			output: []string{
				"devops-can-scale-workloads  default    devops   Group",
			},
		},
		{
			scenario: "Should print who can get pod named `pod-xyz` in the namespace `foo`",
			args:     []string{"get", "pods/pod-xyz", "--namespace=foo"},
			output: []string{
				"batman-can-view-pod-xyz  foo        Batman   User",
			},
		},
		{
			scenario: "Should print who can list pods in group `metrics.k8s.io`",
			args:     []string{"list", "pods.metrics.k8s.io"},
			output: []string{
				"spiderman-can-view-pod-metrics                        Spiderman                           User",
			},
		},
	}
	for _, tt := range data {
		t.Run(tt.scenario, func(t *testing.T) {
			streams, _, out, _ := clioptions.NewTestIOStreams()
			root, err := cmd.NewCmdWhoCan(streams)
			require.NoError(t, err)

			root.SetArgs(tt.args)

			err = root.Execute()
			require.NoError(t, err)

			prettyPrintWhoCanOutput(t, tt.args, out)

			for _, line := range tt.output {
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
	_, err := client.Create(&apiext.CustomResourceDefinition{
		ObjectMeta: meta.ObjectMeta{
			Name: "pods.metrics.k8s.io",
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
	})
	require.NoError(t, err)
}

func configureRBAC(t *testing.T, coreClient client.Interface) {
	t.Helper()

	clientRBAC := coreClient.RbacV1()

	const namespaceFoo = "foo"

	// Configure global namespace
	_, err := clientRBAC.ClusterRoles().Create(&rbac.ClusterRole{
		ObjectMeta: meta.ObjectMeta{Name: "create-configmaps"},
		Rules: []rbac.PolicyRule{
			{
				APIGroups: []string{""},
				Verbs:     []string{"create"},
				Resources: []string{"configmaps"},
			},
		},
	})
	require.NoError(t, err)

	_, err = clientRBAC.ClusterRoles().Create(&rbac.ClusterRole{
		ObjectMeta: meta.ObjectMeta{Name: "get-logs"},
		Rules: []rbac.PolicyRule{
			{
				Verbs:           []string{"get"},
				NonResourceURLs: []string{"/logs"},
			},
		},
	})
	require.NoError(t, err)

	_, err = clientRBAC.ClusterRoles().Create(&rbac.ClusterRole{
		ObjectMeta: meta.ObjectMeta{Name: "view-pod-metrics"},
		Rules: []rbac.PolicyRule{
			{
				Verbs:     []string{"get", "list"},
				APIGroups: []string{"metrics.k8s.io"},
				Resources: []string{"pods"},
			},
		},
	})

	_, err = clientRBAC.ClusterRoleBindings().Create(&rbac.ClusterRoleBinding{
		ObjectMeta: meta.ObjectMeta{Name: "bob-can-get-logs"},
		RoleRef: rbac.RoleRef{
			Name: "get-logs",
			Kind: cmd.ClusterRoleKind,
		},
		Subjects: []rbac.Subject{
			{Kind: rbac.UserKind, Name: "Bob"},
		},
	})
	require.NoError(t, err)

	_, err = clientRBAC.ClusterRoleBindings().Create(&rbac.ClusterRoleBinding{
		ObjectMeta: meta.ObjectMeta{Name: "spiderman-can-view-pod-metrics"},
		RoleRef: rbac.RoleRef{
			Name: "view-pod-metrics",
			Kind: cmd.ClusterRoleKind,
		},
		Subjects: []rbac.Subject{
			{Kind: rbac.UserKind, Name: "Spiderman"},
		},
	})

	// Configure default namespace
	_, err = clientRBAC.Roles(core.NamespaceDefault).Create(&rbac.Role{
		ObjectMeta: meta.ObjectMeta{Name: "create-configmaps"},
		Rules: []rbac.PolicyRule{
			{
				APIGroups: []string{""},
				Verbs:     []string{"create"},
				Resources: []string{"configmaps"},
			},
		},
	})
	require.NoError(t, err)

	_, err = clientRBAC.RoleBindings(core.NamespaceDefault).Create(&rbac.RoleBinding{
		ObjectMeta: meta.ObjectMeta{Name: "alice-can-create-configmaps"},
		RoleRef: rbac.RoleRef{
			Name: "create-configmaps",
			Kind: cmd.RoleKind,
		},
		Subjects: []rbac.Subject{
			{Kind: rbac.UserKind, Name: "Alice"},
		},
	})
	require.NoError(t, err)

	_, err = clientRBAC.RoleBindings(core.NamespaceDefault).Create(&rbac.RoleBinding{
		ObjectMeta: meta.ObjectMeta{Name: "rory-can-create-configmaps"},
		RoleRef: rbac.RoleRef{
			Name: "create-configmaps",
			Kind: cmd.ClusterRoleKind,
		},
		Subjects: []rbac.Subject{
			{Kind: rbac.UserKind, Name: "Rory"},
		},
	})
	require.NoError(t, err)

	_, err = clientRBAC.Roles(core.NamespaceDefault).Create(&rbac.Role{
		ObjectMeta: meta.ObjectMeta{Name: "scale-workloads"},
		Rules: []rbac.PolicyRule{
			{
				APIGroups: []string{"extensions"},
				Verbs:     []string{"update"},
				Resources: []string{"deployments/scale"},
			},
		},
	})

	_, err = clientRBAC.RoleBindings(core.NamespaceDefault).Create(&rbac.RoleBinding{
		ObjectMeta: meta.ObjectMeta{Name: "devops-can-scale-workloads"},
		RoleRef: rbac.RoleRef{
			Name: "scale-workloads",
			Kind: cmd.RoleKind,
		},
		Subjects: []rbac.Subject{
			{Kind: rbac.GroupKind, Name: "devops"},
		},
	})

	// Configure foo namespace
	_, err = coreClient.CoreV1().Namespaces().Create(&core.Namespace{
		ObjectMeta: meta.ObjectMeta{Name: namespaceFoo},
	})
	require.NoError(t, err)

	_, err = clientRBAC.Roles(namespaceFoo).Create(&rbac.Role{
		ObjectMeta: meta.ObjectMeta{Name: "view-services"},
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
	})
	require.NoError(t, err)

	_, err = clientRBAC.Roles(namespaceFoo).Create(&rbac.Role{
		ObjectMeta: meta.ObjectMeta{Name: "view-pod-xyz"},
		Rules: []rbac.PolicyRule{
			{
				APIGroups:     []string{""},
				Verbs:         []string{"get"},
				Resources:     []string{"pods"},
				ResourceNames: []string{"pod-xyz"},
			},
		},
	})

	_, err = clientRBAC.RoleBindings(namespaceFoo).Create(&rbac.RoleBinding{
		ObjectMeta: meta.ObjectMeta{Name: "operator-can-view-services"},
		RoleRef: rbac.RoleRef{
			Name: "view-services",
			Kind: cmd.RoleKind,
		},
		Subjects: []rbac.Subject{
			{Kind: rbac.ServiceAccountKind, Name: "operator", Namespace: "bar"},
		},
	})

	_, err = clientRBAC.RoleBindings(namespaceFoo).Create(&rbac.RoleBinding{
		ObjectMeta: meta.ObjectMeta{Name: "batman-can-view-pod-xyz"},
		RoleRef: rbac.RoleRef{
			Name: "view-pod-xyz",
			Kind: cmd.RoleKind,
		},
		Subjects: []rbac.Subject{
			{Kind: rbac.UserKind, Name: "Batman"},
		},
	})

}
