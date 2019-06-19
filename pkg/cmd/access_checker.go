package cmd

import (
	authz "k8s.io/api/authorization/v1"
	clientauthz "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

type APIAccessChecker interface {
	IsAllowedTo(verb, resource, namespace string) (bool, error)
}

type accessChecker struct {
	client clientauthz.SelfSubjectAccessReviewInterface
}

func NewAPIAccessChecker(client clientauthz.SelfSubjectAccessReviewInterface) APIAccessChecker {
	return &accessChecker{
		client: client,
	}
}

func (ac *accessChecker) IsAllowedTo(verb, resource, namespace string) (bool, error) {
	sar := &authz.SelfSubjectAccessReview{
		Spec: authz.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authz.ResourceAttributes{
				Verb:      verb,
				Resource:  resource,
				Namespace: namespace,
			},
		},
	}

	sar, err := ac.client.Create(sar)
	if err != nil {
		return false, err
	}

	return sar.Status.Allowed, nil
}
