package cmd

import (
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/client-go/kubernetes"
)

type APIAccessChecker interface {
	IsAllowedTo(verb, resource string) (bool, error)
}

type accessChecker struct {
	client kubernetes.Interface
}

func NewAPIAccessChecker(client kubernetes.Interface) APIAccessChecker {
	return &accessChecker{
		client: client,
	}
}

func (ac *accessChecker) IsAllowedTo(verb, resource string) (bool, error) {
	sar := &authzv1.SelfSubjectAccessReview{
		Spec: authzv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb:     verb,
				Resource: resource,
				// TODO Do we set the Namespace property if --namespace flag is passed to the CLI?
				Namespace: "",
			},
		},
	}

	sar, err := ac.client.AuthorizationV1().SelfSubjectAccessReviews().Create(sar)
	if err != nil {
		return false, err
	}

	return sar.Status.Allowed, nil
}
