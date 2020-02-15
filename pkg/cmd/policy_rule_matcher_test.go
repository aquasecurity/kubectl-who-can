package cmd

import (
	"github.com/stretchr/testify/assert"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
				APIGroups: []string{""},
				Resources: []string{"services"},
			},
			{
				Verbs:     []string{"get", "list"},
				APIGroups: []string{"extensions"},
				Resources: []string{"deployments"},
			},
		},
	}
	action := Action{
		Verb: "list",
	}
	gr := schema.GroupResource{
		Group:    "extensions",
		Resource: "deployments",
	}

	// then
	assert.True(t, matcher.MatchesRole(role, action, gr))
}

func TestMatcher_MatchesClusterRole(t *testing.T) {
	// given
	matcher := NewPolicyRuleMatcher()
	role := rbac.ClusterRole{
		ObjectMeta: meta.ObjectMeta{Name: "edit-deployments"},
		Rules: []rbac.PolicyRule{
			{
				Verbs:     []string{"update", "patch", "delete"},
				APIGroups: []string{""},
				Resources: []string{"deployments"},
			},
			{
				Verbs:     []string{"update"},
				APIGroups: []string{"extensions"},
				Resources: []string{"deployments/scale"},
			},
		},
	}
	action := Action{
		Verb:        "update",
		SubResource: "scale",
	}

	gr := schema.GroupResource{
		Group:    "extensions",
		Resource: "deployments",
	}

	// then
	assert.True(t, matcher.MatchesClusterRole(role, action, gr))
}

func TestMatcher_matches(t *testing.T) {
	servicesGR := schema.GroupResource{Resource: "services"}

	data := []struct {
		scenario string

		rule   rbac.PolicyRule
		action Action
		gr     schema.GroupResource

		matches bool
	}{
		{
			scenario: "A",
			action: Action{
				Verb: "get",
			},
			gr: servicesGR,
			rule: rbac.PolicyRule{
				Verbs:     []string{"get", "list"},
				APIGroups: []string{""},
				Resources: []string{"services"},
			},
			matches: true,
		},
		{
			scenario: "B",
			action: Action{
				Verb: "get",
			},
			gr: servicesGR,
			rule: rbac.PolicyRule{
				Verbs:     []string{"get", "list"},
				APIGroups: []string{""},
				Resources: []string{"*"},
			},
			matches: true,
		},
		{
			scenario: "C",
			action: Action{
				Verb: "get",
			},
			gr: servicesGR,
			rule: rbac.PolicyRule{
				Verbs:     []string{rbac.VerbAll},
				APIGroups: []string{""},
				Resources: []string{"services"},
			},
			matches: true,
		},
		{
			scenario: "D",
			action: Action{
				Verb:         "get",
				ResourceName: "mongodb",
			},
			gr: servicesGR,
			rule: rbac.PolicyRule{
				Verbs:     []string{"get", "list"},
				APIGroups: []string{""},
				Resources: []string{"services"},
			},
			matches: true,
		},
		{
			scenario: "E",
			action: Action{
				Verb:         "get",
				ResourceName: "mongodb",
			},
			gr: servicesGR,
			rule: rbac.PolicyRule{
				Verbs:         []string{"get", "list"},
				APIGroups:     []string{""},
				Resources:     []string{"services"},
				ResourceNames: []string{"mongodb", "nginx"},
			},
			matches: true,
		},
		{
			scenario: "F",
			action: Action{
				Verb:         "get",
				ResourceName: "mongodb",
			},
			gr: servicesGR,
			rule: rbac.PolicyRule{
				Verbs:         []string{"get", "list"},
				APIGroups:     []string{""},
				Resources:     []string{"services"},
				ResourceNames: []string{"nginx"},
			},
			matches: false,
		},
		{
			scenario: "G",
			action: Action{
				Verb: "get",
			},
			gr: servicesGR,
			rule: rbac.PolicyRule{
				Verbs:         []string{"get", "list"},
				APIGroups:     []string{""},
				Resources:     []string{"services"},
				ResourceNames: []string{"nginx"},
			},
			matches: false,
		},
		{
			scenario: "H",
			action: Action{
				Verb: "get",
			},
			gr: schema.GroupResource{Resource: "pods"},
			rule: rbac.PolicyRule{
				Verbs:     []string{"create"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
			},
			matches: false,
		},
		{
			scenario: "I",
			action: Action{
				Verb: "get",
			},
			gr: schema.GroupResource{Resource: "persistentvolumes"},
			rule: rbac.PolicyRule{
				Verbs:     []string{"get"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
			},
			matches: false,
		},
		{
			scenario: "J",
			action:   Action{Verb: "get", NonResourceURL: "/logs"},
			rule: rbac.PolicyRule{
				Verbs:           []string{"get"},
				NonResourceURLs: []string{"/logs"},
			},
			matches: true,
		},
		{
			scenario: "K",
			action:   Action{Verb: "get", NonResourceURL: "/logs"},
			rule: rbac.PolicyRule{
				Verbs:           []string{"post"},
				NonResourceURLs: []string{"/logs"},
			},
			matches: false,
		},
		{
			scenario: "L",
			action:   Action{Verb: "get", NonResourceURL: "/logs"},
			rule: rbac.PolicyRule{
				Verbs:           []string{"get"},
				NonResourceURLs: []string{"/api"},
			},
			matches: false,
		},
		{
			scenario: "Should return true when PolicyRule's APIGroup matches resolved resource's group",
			action: Action{
				Verb: "get",
			},
			gr: schema.GroupResource{Resource: "deployments", Group: "extensions"},
			rule: rbac.PolicyRule{
				Verbs:     []string{"get"},
				APIGroups: []string{"extensions"},
				Resources: []string{"deployments"},
			},
			matches: true,
		},
		{
			scenario: "Should return true when PolicyRule's APIGroup matches all ('*') resource groups",
			action: Action{
				Verb: "get",
			},
			gr: schema.GroupResource{Resource: "pods", Group: "metrics.k8s.io"},
			rule: rbac.PolicyRule{
				Verbs:     []string{"get"},
				APIGroups: []string{"*"},
				Resources: []string{"pods"},
			},
			matches: true,
		},
		{
			scenario: "Should return false when PolicyRule's APIGroup doesn't match resolved resource's Group",
			action: Action{
				Verb: "get",
			},
			gr: schema.GroupResource{Resource: "pods", Group: "metrics.k8s.io"},
			rule: rbac.PolicyRule{
				Verbs:     []string{"get"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
			},
			matches: false,
		},
	}

	// given
	policyRuleMatcher := matcher{}

	for _, tt := range data {
		t.Run(tt.scenario, func(t *testing.T) {
			// when
			matches := policyRuleMatcher.matches(tt.rule, tt.action, tt.gr)

			// then
			assert.Equal(t, tt.matches, matches)
		})
	}

}
