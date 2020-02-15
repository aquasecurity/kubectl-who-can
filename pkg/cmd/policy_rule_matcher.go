package cmd

import (
	"github.com/golang/glog"
	rbac "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// PolicyRuleMatcher wraps the Matches* methods.
//
// MatchesRole returns `true` if any PolicyRule defined by the given Role matches the specified Action, `false` otherwise.
//
// MatchesClusterRole returns `true` if any PolicyRule defined by the given ClusterRole matches the specified Action, `false` otherwise.
type PolicyRuleMatcher interface {
	MatchesRole(role rbac.Role, action Action, gr schema.GroupResource) bool
	MatchesClusterRole(role rbac.ClusterRole, action Action, gr schema.GroupResource) bool
}

type matcher struct {
}

// NewPolicyRuleMatcher constructs the default PolicyRuleMatcher.
func NewPolicyRuleMatcher() PolicyRuleMatcher {
	return &matcher{}
}

func (m *matcher) MatchesRole(role rbac.Role, action Action, gr schema.GroupResource) bool {
	for _, rule := range role.Rules {
		if !m.matches(rule, action, gr) {
			continue
		}
		glog.V(4).Infof("Role [%s] matches action filter? YES", role.Name)
		return true
	}
	glog.V(4).Infof("Role [%s] matches action filter? NO", role.Name)
	return false
}

func (m *matcher) MatchesClusterRole(role rbac.ClusterRole, action Action, gr schema.GroupResource) bool {
	for _, rule := range role.Rules {
		if !m.matches(rule, action, gr) {
			continue
		}

		glog.V(4).Infof("ClusterRole [%s] matches action filter? YES", role.Name)
		return true
	}
	glog.V(4).Infof("ClusterRole [%s] matches action filter? NO", role.Name)
	return false
}

// matches returns `true` if the given PolicyRule matches the specified Action, `false` otherwise.
func (m *matcher) matches(rule rbac.PolicyRule, action Action, gr schema.GroupResource) bool {
	if action.NonResourceURL != "" {
		return m.matchesVerb(rule, action.Verb) &&
			m.matchesNonResourceURL(rule, action.NonResourceURL)
	}

	resource := gr.Resource
	if action.SubResource != "" {
		resource += "/" + action.SubResource
	}

	return m.matchesVerb(rule, action.Verb) &&
		m.matchesResource(rule, resource) &&
		m.matchesAPIGroup(rule, gr.Group) &&
		m.matchesResourceName(rule, action.ResourceName)
}

func (m *matcher) matchesAPIGroup(rule rbac.PolicyRule, actionGroup string) bool {
	for _, group := range rule.APIGroups {
		if group == rbac.APIGroupAll || group == actionGroup {
			return true
		}
	}
	return false
}

func (m *matcher) matchesVerb(rule rbac.PolicyRule, actionVerb string) bool {
	for _, verb := range rule.Verbs {
		if verb == rbac.VerbAll || verb == actionVerb {
			return true
		}
	}
	return false
}

func (m *matcher) matchesResource(rule rbac.PolicyRule, actionResource string) bool {
	for _, resource := range rule.Resources {
		if resource == rbac.ResourceAll || resource == actionResource {
			return true
		}
	}
	return false
}

func (m *matcher) matchesResourceName(rule rbac.PolicyRule, actionResourceName string) bool {
	if actionResourceName == "" && len(rule.ResourceNames) == 0 {
		return true
	}
	if len(rule.ResourceNames) == 0 {
		return true
	}
	for _, name := range rule.ResourceNames {
		if name == actionResourceName {
			return true
		}
	}
	return false
}

func (m *matcher) matchesNonResourceURL(rule rbac.PolicyRule, actionNonResourceURL string) bool {
	for _, URL := range rule.NonResourceURLs {
		if URL == actionNonResourceURL {
			return true
		}
	}
	return false
}
