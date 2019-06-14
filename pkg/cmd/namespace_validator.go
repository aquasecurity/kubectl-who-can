package cmd

import (
	"fmt"
	apicorev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

type NamespaceValidator interface {
	Validate(name string) error
}

type namespaceValidator struct {
	client typedcorev1.NamespaceInterface
}

func NewNamespaceValidator(client typedcorev1.NamespaceInterface) NamespaceValidator {
	return &namespaceValidator{
		client: client,
	}
}

func (w *namespaceValidator) Validate(name string) error {
	if name != apicorev1.NamespaceAll {
		ns, err := w.client.Get(name, metav1.GetOptions{})
		if err != nil {
			if statusErr, ok := err.(*errors.StatusError); ok &&
				statusErr.Status().Reason == metav1.StatusReasonNotFound {
				return fmt.Errorf("\"%s\" not found", name)
			}
			return fmt.Errorf("getting namespace: %v", err)
		}
		if ns.Status.Phase != apicorev1.NamespaceActive {
			return fmt.Errorf("invalid status: %v", ns.Status.Phase)
		}
	}
	return nil
}
