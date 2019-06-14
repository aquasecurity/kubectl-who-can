package cmd

import (
	"fmt"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/restmapper"
)

// ResourceResolver wraps the Resolve method.
//
// Resolve attempts to resolve a APIResource by `resourceArg` and validate that the specified `verbArg` is supported.
type ResourceResolver interface {
	Resolve(verbArg, resourceArg string) (v1.APIResource, error)
}

type resourceResolver struct {
	client discovery.DiscoveryInterface
}

func NewResourceResolver(client discovery.DiscoveryInterface) ResourceResolver {
	return &resourceResolver{
		client: client,
	}
}

func (rv *resourceResolver) Resolve(verbArg, resourceArg string) (v1.APIResource, error) {
	resource, err := rv.resourceFor(resourceArg)
	if err != nil {
		return v1.APIResource{}, fmt.Errorf("resolving resource: %v", err)
	}

	if resource.Name == "" {
		return v1.APIResource{}, fmt.Errorf("the server doesn't have a resource type \"%s\"", resourceArg)
	}

	if !rv.isVerbSupportedBy(verbArg, resource) {
		return v1.APIResource{}, fmt.Errorf("the \"%s\" resource does not support the \"%s\" verb, only %v", resourceArg, verbArg, resource.Verbs)
	}

	return resource, nil
}

func (rv *resourceResolver) resourceFor(resourceArg string) (v1.APIResource, error) {
	index, err := rv.indexResources()
	if err != nil {
		return v1.APIResource{}, err
	}

	resource, ok := index[resourceArg]
	if ok {
		return resource, nil
	}

	groupResources, err := restmapper.GetAPIGroupResources(rv.client)
	if err != nil {
		return v1.APIResource{}, err
	}

	mapper := restmapper.NewDiscoveryRESTMapper(groupResources)
	gvr, err := mapper.ResourceFor(schema.GroupVersionResource{Resource: resourceArg})
	if err != nil {
		return v1.APIResource{}, nil
	}
	return index[gvr.Resource], nil
}

// indexResources builds a lookup index for APIResources where the keys are resources names (both plural and short names).
func (rv *resourceResolver) indexResources() (map[string]v1.APIResource, error) {
	serverResources := make(map[string]v1.APIResource)

	serverGroups, err := rv.client.ServerGroups()
	if err != nil {
		return nil, fmt.Errorf("getting API groups: %v", err)
	}
	for _, sg := range serverGroups.Groups {
		for _, version := range sg.Versions {
			// Consider only preferred versions
			if version.GroupVersion != sg.PreferredVersion.GroupVersion {
				continue
			}
			rsList, err := rv.client.ServerResourcesForGroupVersion(version.GroupVersion)
			if err != nil {
				return nil, fmt.Errorf("getting resources for API group: %v", err)
			}

			for _, res := range rsList.APIResources {
				serverResources[res.Name] = res
				if len(res.ShortNames) > 0 {
					for _, sn := range res.ShortNames {
						serverResources[sn] = res
					}
				}
			}
		}
	}
	return serverResources, nil
}

// isVerbSupportedBy returns `true` if the given verbArg is supported by the given resourceArg, `false` otherwise.
func (rv *resourceResolver) isVerbSupportedBy(verb string, resource v1.APIResource) bool {
	supported := false
	for _, v := range resource.Verbs {
		if v == verb {
			supported = true
		}
	}
	return supported
}
