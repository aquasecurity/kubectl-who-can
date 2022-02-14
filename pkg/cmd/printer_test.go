package cmd_test

import (
	"bytes"
	"testing"

	"github.com/aquasecurity/kubectl-who-can/pkg/cmd"
	"github.com/stretchr/testify/assert"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPrinter_PrintWarnings(t *testing.T) {

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
			cmd.NewPrinter(&buf, false).PrintWarnings(tt.warnings)
			assert.Equal(t, tt.expectedOutput, buf.String())
		})
	}
}

// TODO Use more descriptive names for test cases rather than A, B, C, ...
func TestPrinter_PrintChecks(t *testing.T) {
	testCases := []struct {
		scenario string

		verb           string
		resource       string
		nonResourceURL string
		resourceName   string

		roleBindings        []rbac.RoleBinding
		clusterRoleBindings []rbac.ClusterRoleBinding

		wide   bool
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
		{
			scenario: "E",
			verb:     "get", resource: "pods",
			roleBindings: []rbac.RoleBinding{
				{
					ObjectMeta: meta.ObjectMeta{Name: "Alice-can-view-pods", Namespace: "default"},
					RoleRef: rbac.RoleRef{
						Kind: cmd.RoleKind,
						Name: "view-pods",
					},
					Subjects: []rbac.Subject{
						{Name: "Alice", Kind: "User"},
					}},
				{
					ObjectMeta: meta.ObjectMeta{Name: "Admins-can-view-pods", Namespace: "bar"},
					RoleRef: rbac.RoleRef{
						Kind: cmd.ClusterRoleKind,
						Name: "view",
					},
					Subjects: []rbac.Subject{
						{Name: "Admins", Kind: "Group"},
					}},
			},
			clusterRoleBindings: []rbac.ClusterRoleBinding{
				{
					ObjectMeta: meta.ObjectMeta{Name: "Bob-and-Eve-can-view-pods", Namespace: "default"},
					RoleRef: rbac.RoleRef{
						Kind: cmd.ClusterRoleKind,
						Name: "view",
					},
					Subjects: []rbac.Subject{
						{Name: "Bob", Kind: "ServiceAccount", Namespace: "foo"},
						{Name: "Eve", Kind: "User"},
					},
				},
			},
			wide: true,
			output: `ROLEBINDING           ROLE              NAMESPACE  SUBJECT  TYPE   SA-NAMESPACE
Alice-can-view-pods   Role/view-pods    default    Alice    User   
Admins-can-view-pods  ClusterRole/view  bar        Admins   Group  

CLUSTERROLEBINDING         ROLE              SUBJECT  TYPE            SA-NAMESPACE
Bob-and-Eve-can-view-pods  ClusterRole/view  Bob      ServiceAccount  foo
Bob-and-Eve-can-view-pods  ClusterRole/view  Eve      User            
`,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.scenario, func(t *testing.T) {
			// given
			var buf bytes.Buffer
			action := cmd.Action{
				Verb:           tt.verb,
				Resource:       tt.resource,
				NonResourceURL: tt.nonResourceURL,
				ResourceName:   tt.resourceName,
			}

			// when
			cmd.NewPrinter(&buf, tt.wide).
				PrintChecks(action, tt.roleBindings, tt.clusterRoleBindings)

			// then
			assert.Equal(t, tt.output, buf.String())
		})

	}

}

func TestPrinter_ExportData(t *testing.T) {
	testCases := []struct {
		scenario string

		verb           string
		resource       string
		nonResourceURL string
		resourceName   string

		roleBindings        []rbac.RoleBinding
		clusterRoleBindings []rbac.ClusterRoleBinding

		wide   bool
		output string
	}{
		{
			scenario: "A",
			verb:     "get", resource: "pods", resourceName: "",
			output: "{}\n",
		},
		{
			scenario: "B",
			verb:     "get", resource: "pods", resourceName: "my-pod",
			output: "{}\n",
		},
		{
			scenario: "C",
			verb:     "get", nonResourceURL: "/healthz",
			output: "{}\n",
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
			output: "{\n    \"clusterRoleBindings\": [\n        {\n            \"name\": \"Bob-and-Eve-can-view-pods\",\n            \"roleRef\": {\n                \"apiGroup\": \"\",\n                \"kind\": \"\",\n                \"name\": \"\"\n            },\n            \"subjects\": [\n                {\n                    \"kind\": \"ServiceAccount\",\n                    \"name\": \"Bob\",\n                    \"namespace\": \"foo\"\n                },\n                {\n                    \"kind\": \"User\",\n                    \"name\": \"Eve\"\n                }\n            ]\n        }\n    ],\n    \"roleBindings\": [\n        {\n            \"name\": \"Alice-can-view-pods\",\n            \"roleRef\": {\n                \"apiGroup\": \"\",\n                \"kind\": \"\",\n                \"name\": \"\"\n            },\n            \"subjects\": [\n                {\n                    \"kind\": \"User\",\n                    \"name\": \"Alice\"\n                }\n            ]\n        },\n        {\n            \"name\": \"Admins-can-view-pods\",\n            \"roleRef\": {\n                \"apiGroup\": \"\",\n                \"kind\": \"\",\n                \"name\": \"\"\n            },\n            \"subjects\": [\n                {\n                    \"kind\": \"Group\",\n                    \"name\": \"Admins\"\n                }\n            ]\n        }\n    ]\n}\n",
		},
		{
			scenario: "E",
			verb:     "get", resource: "pods",
			roleBindings: []rbac.RoleBinding{
				{
					ObjectMeta: meta.ObjectMeta{Name: "Alice-can-view-pods", Namespace: "default"},
					RoleRef: rbac.RoleRef{
						Kind: cmd.RoleKind,
						Name: "view-pods",
					},
					Subjects: []rbac.Subject{
						{Name: "Alice", Kind: "User"},
					}},
				{
					ObjectMeta: meta.ObjectMeta{Name: "Admins-can-view-pods", Namespace: "bar"},
					RoleRef: rbac.RoleRef{
						Kind: cmd.ClusterRoleKind,
						Name: "view",
					},
					Subjects: []rbac.Subject{
						{Name: "Admins", Kind: "Group"},
					}},
			},
			clusterRoleBindings: []rbac.ClusterRoleBinding{
				{
					ObjectMeta: meta.ObjectMeta{Name: "Bob-and-Eve-can-view-pods", Namespace: "default"},
					RoleRef: rbac.RoleRef{
						Kind: cmd.ClusterRoleKind,
						Name: "view",
					},
					Subjects: []rbac.Subject{
						{Name: "Bob", Kind: "ServiceAccount", Namespace: "foo"},
						{Name: "Eve", Kind: "User"},
					},
				},
			},
			wide:   true,
			output: "{\n    \"clusterRoleBindings\": [\n        {\n            \"name\": \"Bob-and-Eve-can-view-pods\",\n            \"roleRef\": {\n                \"apiGroup\": \"\",\n                \"kind\": \"ClusterRole\",\n                \"name\": \"view\"\n            },\n            \"subjects\": [\n                {\n                    \"kind\": \"ServiceAccount\",\n                    \"name\": \"Bob\",\n                    \"namespace\": \"foo\"\n                },\n                {\n                    \"kind\": \"User\",\n                    \"name\": \"Eve\"\n                }\n            ]\n        }\n    ],\n    \"roleBindings\": [\n        {\n            \"name\": \"Alice-can-view-pods\",\n            \"roleRef\": {\n                \"apiGroup\": \"\",\n                \"kind\": \"Role\",\n                \"name\": \"view-pods\"\n            },\n            \"subjects\": [\n                {\n                    \"kind\": \"User\",\n                    \"name\": \"Alice\"\n                }\n            ]\n        },\n        {\n            \"name\": \"Admins-can-view-pods\",\n            \"roleRef\": {\n                \"apiGroup\": \"\",\n                \"kind\": \"ClusterRole\",\n                \"name\": \"view\"\n            },\n            \"subjects\": [\n                {\n                    \"kind\": \"Group\",\n                    \"name\": \"Admins\"\n                }\n            ]\n        }\n    ]\n}\n",
		},
		{
			scenario: "F",
			verb:     "get", resource: "pods",
			roleBindings: []rbac.RoleBinding{
				{
					ObjectMeta: meta.ObjectMeta{Name: "Alice-can-view-pods", Namespace: "default"},
					Subjects:   []rbac.Subject{},
				},
			},
			clusterRoleBindings: []rbac.ClusterRoleBinding{
				{
					ObjectMeta: meta.ObjectMeta{Name: "Bob-and-Eve-can-view-pods", Namespace: "default"},
					Subjects:   []rbac.Subject{},
				},
			},
			output: "{\n    \"clusterRoleBindings\": [],\n    \"roleBindings\": []\n}\n",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.scenario, func(t *testing.T) {
			// given
			var buf bytes.Buffer
			action := cmd.Action{
				Verb:           tt.verb,
				Resource:       tt.resource,
				NonResourceURL: tt.nonResourceURL,
				ResourceName:   tt.resourceName,
			}

			// when
			cmd.NewPrinter(&buf, tt.wide).
				ExportData(action, tt.roleBindings, tt.clusterRoleBindings)

			// then
			assert.Equal(t, tt.output, buf.String())
		})
	}
}
