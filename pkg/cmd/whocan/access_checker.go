package whocan

import (
	authzv1 "k8s.io/api/authorization/v1"
	v1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

type APIAccessChecker interface {
	IsAllowedTo(verb, resource, namespace string) (bool, error)
}

type accessChecker struct {
	client v1.SelfSubjectAccessReviewInterface
}

func NewAPIAccessChecker(client v1.SelfSubjectAccessReviewInterface) APIAccessChecker {
	return &accessChecker{
		client: client,
	}
}

func (ac *accessChecker) IsAllowedTo(verb, resource, namespace string) (bool, error) {
	sar := &authzv1.SelfSubjectAccessReview{
		Spec: authzv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authzv1.ResourceAttributes{
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
