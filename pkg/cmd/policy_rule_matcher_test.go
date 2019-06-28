package cmd

import (
	"github.com/stretchr/testify/assert"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func TestMatcher_MatchesRole(t *testing.T) {
	// given
	matcher := NewPolicyRuleMatcher()
	role := rbac.Role{
		ObjectMeta: meta.ObjectMeta{Name: "view-services"},
		Rules: []rbac.PolicyRule{
			{
				Verbs:     []string{"get", "list"},
				Resources: []string{"services"},
			},
			{
				Verbs:     []string{"get", "list"},
				Resources: []string{"endpoints"},
			},
		},
	}
	action := Action{verb: "list", resource: "endpoints"}

	// then
	assert.True(t, matcher.MatchesRole(role, action))
}

func TestMatcher_MatchesClusterRole(t *testing.T) {
	// given
	matcher := NewPolicyRuleMatcher()
	role := rbac.ClusterRole{
		ObjectMeta: meta.ObjectMeta{Name: "edit-deployments"},
		Rules: []rbac.PolicyRule{
			{
				Verbs:     []string{"update", "patch", "delete"},
				Resources: []string{"deployments"},
			},
			{
				Verbs:     []string{"update"},
				Resources: []string{"deployments/scale"},
			},
		},
	}
	action := Action{verb: "update", resource: "deployments/scale"}

	// then
	assert.True(t, matcher.MatchesClusterRole(role, action))
}

func TestMatcher_matches(t *testing.T) {
	data := []struct {
		scenario string

		rule   rbac.PolicyRule
		action Action

		matches bool
	}{
		{
			scenario: "A",
			action:   Action{verb: "get", resource: "services", resourceName: ""},
			rule: rbac.PolicyRule{
				Verbs:     []string{"get", "list"},
				Resources: []string{"services"},
			},
			matches: true,
		},
		{
			scenario: "B",
			action:   Action{verb: "get", resource: "services", resourceName: ""},
			rule: rbac.PolicyRule{
				Verbs:     []string{"get", "list"},
				Resources: []string{"*"},
			},
			matches: true,
		},
		{
			scenario: "C",
			action:   Action{verb: "get", resource: "services", resourceName: ""},
			rule: rbac.PolicyRule{
				Verbs:     []string{"*"},
				Resources: []string{"services"},
			},
			matches: true,
		},
		{
			scenario: "D",
			action:   Action{verb: "get", resource: "services", resourceName: "mongodb"},
			rule: rbac.PolicyRule{
				Verbs:     []string{"get", "list"},
				Resources: []string{"services"},
			},
			matches: true,
		},
		{
			scenario: "E",
			action:   Action{verb: "get", resource: "services", resourceName: "mongodb"},
			rule: rbac.PolicyRule{
				Verbs:         []string{"get", "list"},
				Resources:     []string{"services"},
				ResourceNames: []string{"mongodb", "nginx"},
			},
			matches: true,
		},
		{
			scenario: "F",
			action:   Action{verb: "get", resource: "services", resourceName: "mongodb"},
			rule: rbac.PolicyRule{
				Verbs:         []string{"get", "list"},
				Resources:     []string{"services"},
				ResourceNames: []string{"nginx"},
			},
			matches: false,
		},
		{
			scenario: "G",
			action:   Action{verb: "get", resource: "services", resourceName: ""},
			rule: rbac.PolicyRule{
				Verbs:         []string{"get", "list"},
				Resources:     []string{"services"},
				ResourceNames: []string{"nginx"},
			},
			matches: false,
		},
		{
			scenario: "H",
			action:   Action{verb: "get", resource: "pods", resourceName: ""},
			rule: rbac.PolicyRule{
				Verbs:     []string{"create"},
				Resources: []string{"pods"},
			},
			matches: false,
		},
		{
			scenario: "I",
			action:   Action{verb: "get", resource: "persistentvolumes", resourceName: ""},
			rule: rbac.PolicyRule{
				Verbs:     []string{"get"},
				Resources: []string{"pods"},
			},
			matches: false,
		},
		{
			scenario: "J",
			action:   Action{verb: "get", nonResourceURL: "/logs"},
			rule: rbac.PolicyRule{
				Verbs:           []string{"get"},
				NonResourceURLs: []string{"/logs"},
			},
			matches: true,
		},
		{
			scenario: "K",
			action:   Action{verb: "get", nonResourceURL: "/logs"},
			rule: rbac.PolicyRule{
				Verbs:           []string{"post"},
				NonResourceURLs: []string{"/logs"},
			},
			matches: false,
		},
		{
			scenario: "L",
			action:   Action{verb: "get", nonResourceURL: "/logs"},
			rule: rbac.PolicyRule{
				Verbs:           []string{"get"},
				NonResourceURLs: []string{"/api"},
			},
			matches: false,
		},
	}

	// given
	policyRuleMatcher := matcher{}

	for _, tt := range data {
		t.Run(tt.scenario, func(t *testing.T) {
			// when
			matches := policyRuleMatcher.matches(tt.rule, tt.action)

			// then
			assert.Equal(t, tt.matches, matches)
		})
	}

}
