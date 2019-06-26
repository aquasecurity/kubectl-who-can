package cmd

import (
	"fmt"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientcore "k8s.io/client-go/kubernetes/typed/core/v1"
)

type NamespaceValidator interface {
	Validate(name string) error
}

type namespaceValidator struct {
	client clientcore.NamespaceInterface
}

func NewNamespaceValidator(client clientcore.NamespaceInterface) NamespaceValidator {
	return &namespaceValidator{
		client: client,
	}
}

func (w *namespaceValidator) Validate(name string) error {
	if name != core.NamespaceAll {
		ns, err := w.client.Get(name, meta.GetOptions{})
		if err != nil {
			if statusErr, ok := err.(*errors.StatusError); ok &&
				statusErr.Status().Reason == meta.StatusReasonNotFound {
				return fmt.Errorf("\"%s\" not found", name)
			}
			return fmt.Errorf("getting namespace: %v", err)
		}
		if ns.Status.Phase != core.NamespaceActive {
			return fmt.Errorf("invalid status: %v", ns.Status.Phase)
		}
	}
	return nil
}
