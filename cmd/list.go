package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/golang/glog"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

func (w *whoCan) do() error {
	w.r = make(map[role]struct{}, 10)

	// Get the Roles that relate to the Verbs and Resources we are interested in
	err := w.getRoles()
	if err != nil {
		return fmt.Errorf("getting Roles: %v", err)
	}

	// Get the RoleBindings that relate to this set of Roles
	roleBindings, err := w.getRoleBindings()
	if err != nil {
		return fmt.Errorf("getting RoleBindings: %v", err)
	}

	// Get the ClusterRoles that relate to the verbs and resources we are interested in
	err = w.getClusterRoles()
	if err != nil {
		return fmt.Errorf("getting ClusterRoles: %v", err)
	}

	// Get the ClusterRoleBindings that relate to this set of ClusterRoles
	clusterRoleBindings, err := w.getClusterRoleBindings()
	if err != nil {
		return fmt.Errorf("getting ClusterRoleBindings: %v", err)
	}

	// Output the results
	w.output(roleBindings, clusterRoleBindings)

	// TODO!! Check the user's own permissions to see if we might be missing something in the output
	return nil
}

func (w *whoCan) getRoles() error {
	rl, err := w.client.RbacV1().Roles("").List(metav1.ListOptions{})
	if err != nil {
		return err
	}

	w.filterRoles(rl)
	return nil
}

func (w *whoCan) getClusterRoles() error {
	crl, err := w.client.RbacV1().ClusterRoles().List(metav1.ListOptions{})
	if err != nil {
		return err
	}

	w.filterClusterRoles(crl)
	return nil
}

func (w *whoCan) filterRoles(rl *rbacv1.RoleList) {
	// Only interested in Roles that relate to the verbs and resources we care about
	for _, item := range rl.Items {
		// Roles contain PolicyRules
		for _, rule := range item.Rules {
			w.policyRuleMatch(rule, item.Name, false)
		}
	}
}

func (w *whoCan) filterClusterRoles(rl *rbacv1.ClusterRoleList) {
	// Only interested in ClusterRoles that relate to the verbs and resources we care about
	for _, item := range rl.Items {
		glog.V(3).Info(fmt.Sprintf("Cluster Role: %s", item.Name))
		// Roles contain PolicyRules
		for _, rule := range item.Rules {
			w.policyRuleMatch(rule, item.Name, true)
		}
	}
}

func (w *whoCan) policyRuleMatch(rule rbacv1.PolicyRule, roleName string, isClusterRole bool) {
	glog.V(3).Info(fmt.Sprintf("  Rule: %v", rule))
	for _, resource := range rule.Resources {
		if resource == w.resource || resource == rbacv1.ResourceAll {
			glog.V(2).Info(fmt.Sprintf("  Resource match %s in role %s", resource, roleName))
			for _, verb := range rule.Verbs {
				if verb == w.verb || verb == rbacv1.VerbAll {
					glog.V(2).Info(fmt.Sprintf("    Verb match %s in role %s", verb, roleName))
					newRole := role{
						name:          roleName,
						isClusterRole: isClusterRole,
					}
					if _, ok := w.r[newRole]; !ok {
						w.r[newRole] = struct{}{}
					}
				}
			}
		}
	}
}

func (w *whoCan) getRoleBindings() (roleBindings []rbacv1.RoleBinding, err error) {
	rbl, err := w.client.RbacV1().RoleBindings("").List(metav1.ListOptions{})
	if err != nil {
		return
	}

	for _, roleBinding := range rbl.Items {
		if w.r.match(&roleBinding.RoleRef) {
			glog.V(1).Info(fmt.Sprintf("Match found: roleRef: %v", roleBinding.RoleRef))
			roleBindings = append(roleBindings, roleBinding)
		}
	}

	return
}

func (w *whoCan) getClusterRoleBindings() (clusterRoleBindings []rbacv1.ClusterRoleBinding, err error) {
	rbl, err := w.client.RbacV1().ClusterRoleBindings().List(metav1.ListOptions{})
	if err != nil {
		return
	}

	for _, roleBinding := range rbl.Items {
		if w.r.match(&roleBinding.RoleRef) {
			glog.V(1).Info(fmt.Sprintf("Match found: roleRef: %v", roleBinding.RoleRef))
			clusterRoleBindings = append(clusterRoleBindings, roleBinding)
		}
	}

	return
}

func (r roles) match(roleRef *rbacv1.RoleRef) bool {
	tempRole := role{
		name:          roleRef.Name,
		isClusterRole: (roleRef.Kind == "ClusterRole"),
	}

	glog.V(3).Info(fmt.Sprintf("Testing against roleRef: %v", tempRole))

	_, ok := r[tempRole]
	return ok
}

func (w *whoCan) output(roleBindings []rbacv1.RoleBinding, clusterRoleBindings []rbacv1.ClusterRoleBinding) {
	wr := new(tabwriter.Writer)
	wr.Init(os.Stdout, 0, 8, 2, ' ', 0)

	if len(roleBindings) == 0 {
		fmt.Printf("No subjects found with permissions to %s %s assigned through RoleBindings\n", w.verb, w.resource)
	} else {
		fmt.Fprintln(wr, "ROLEBINDING\tNAMESPACE\tSUBJECT\tTYPE\tSA-NAMESPACE")
		for _, rb := range roleBindings {
			for _, s := range rb.Subjects {
				fmt.Fprintf(wr, "%s\t%s\t%s\t%s\t%s\n", rb.Name, rb.GetNamespace(), s.Name, s.Kind, s.Namespace)
			}
		}
	}

	fmt.Fprintln(wr)

	if len(clusterRoleBindings) == 0 {
		fmt.Printf("No subjects found with permissions to %s %s assigned through ClusterRoleBindings\n", w.verb, w.resource)
	} else {
		fmt.Fprintln(wr, "CLUSTERROLEBINDING\tSUBJECT\tTYPE\tSA-NAMESPACE")
		for _, rb := range clusterRoleBindings {
			for _, s := range rb.Subjects {
				fmt.Fprintf(wr, "%s\t%s\t%s\t%s\n", rb.Name, s.Name, s.Kind, s.Namespace)
			}
		}
	}
	wr.Flush()
}
