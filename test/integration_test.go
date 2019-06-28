package test

import (
	"github.com/aquasecurity/kubectl-who-can/pkg/cmd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	clioptions "k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	clientrbac "k8s.io/client-go/kubernetes/typed/rbac/v1"
	"k8s.io/client-go/tools/clientcmd"
	"os"
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

	kubeClient, err := kubernetes.NewForConfig(config)
	require.NoError(t, err)

	configureRBAC(t, kubeClient.RbacV1())

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
	}
	for _, tt := range data {
		t.Run(tt.scenario, func(t *testing.T) {
			streams, _, out, _ := clioptions.NewTestIOStreams()
			root, err := cmd.NewCmdWhoCan(streams)
			require.NoError(t, err)

			root.SetArgs(tt.args)

			err = root.Execute()
			require.NoError(t, err)

			t.Logf("\n%s\n", out.String())

			for _, line := range tt.output {
				assert.Contains(t, out.String(), line)
			}
		})
	}

}

func configureRBAC(t *testing.T, clientRBAC clientrbac.RbacV1Interface) {
	t.Helper()

	_, err := clientRBAC.ClusterRoles().Create(&rbac.ClusterRole{
		ObjectMeta: meta.ObjectMeta{Name: "create-configmaps"},
		Rules: []rbac.PolicyRule{
			{
				APIGroups: []string{"v1"},
				Verbs:     []string{"create"},
				Resources: []string{"configmaps"},
			},
		},
	})
	require.NoError(t, err)

	_, err = clientRBAC.Roles("default").Create(&rbac.Role{
		ObjectMeta: meta.ObjectMeta{Name: "create-configmaps"},
		Rules: []rbac.PolicyRule{
			{
				APIGroups: []string{"v1"},
				Verbs:     []string{"create"},
				Resources: []string{"configmaps"},
			},
		},
	})
	require.NoError(t, err)

	_, err = clientRBAC.RoleBindings("default").Create(&rbac.RoleBinding{
		ObjectMeta: meta.ObjectMeta{Name: "alice-can-create-configmaps"},
		RoleRef:    rbac.RoleRef{Name: "create-configmaps", Kind: "Role"},
		Subjects: []rbac.Subject{
			{Name: "Alice", Kind: "User"},
		},
	})
	require.NoError(t, err)

	_, err = clientRBAC.RoleBindings("default").Create(&rbac.RoleBinding{
		ObjectMeta: meta.ObjectMeta{Name: "rory-can-create-configmaps"},
		RoleRef:    rbac.RoleRef{Name: "create-configmaps", Kind: "ClusterRole"},
		Subjects: []rbac.Subject{
			{Name: "Rory", Kind: "User"},
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

	_, err = clientRBAC.ClusterRoleBindings().Create(&rbac.ClusterRoleBinding{
		ObjectMeta: meta.ObjectMeta{Name: "bob-can-get-logs"},
		RoleRef:    rbac.RoleRef{Name: "get-logs", Kind: "ClusterRole"},
		Subjects: []rbac.Subject{
			{Name: "Bob", Kind: "User"},
		},
	})
	require.NoError(t, err)

}
