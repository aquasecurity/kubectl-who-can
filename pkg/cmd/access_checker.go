package cmd

import (
	"context"

	authz "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthz "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

// AccessChecker wraps the IsAllowedTo method.
//
// IsAllowedTo checks whether the current user is allowed to perform the given action in the specified namespace.
// Specifying "" as namespace performs check in all namespaces.
type AccessChecker interface {
	IsAllowedTo(ctx context.Context, verb, resource, namespace string, opts metav1.CreateOptions) (bool, error)
}

type accessChecker struct {
	client clientauthz.SelfSubjectAccessReviewInterface
}

// NewAccessChecker constructs the default AccessChecker.
func NewAccessChecker(client clientauthz.SelfSubjectAccessReviewInterface) AccessChecker {
	return &accessChecker{
		client: client,
	}
}

func (ac *accessChecker) IsAllowedTo(ctx context.Context, verb, resource, namespace string, opts metav1.CreateOptions) (bool, error) {
	sar := &authz.SelfSubjectAccessReview{
		Spec: authz.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authz.ResourceAttributes{
				Verb:      verb,
				Resource:  resource,
				Namespace: namespace,
			},
		},
	}

	sar, err := ac.client.Create(ctx, sar, opts)
	if err != nil {
		return false, err
	}

	return sar.Status.Allowed, nil
}
