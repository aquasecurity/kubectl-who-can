package cmd

import (
	"github.com/stretchr/testify/mock"
	rbac "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type policyRuleMatcherMock struct {
	mock.Mock
}

func (prm *policyRuleMatcherMock) MatchesRole(role rbac.Role, action Action, gr schema.GroupResource) bool {
	args := prm.Called(role, action, gr)
	return args.Bool(0)
}

func (prm *policyRuleMatcherMock) MatchesClusterRole(role rbac.ClusterRole, action Action, gr schema.GroupResource) bool {
	args := prm.Called(role, action, gr)
	return args.Bool(0)
}
