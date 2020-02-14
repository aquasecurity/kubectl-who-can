module github.com/aquasecurity/kubectl-who-can

go 1.12

require (
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/spf13/cobra v0.0.4
	github.com/spf13/pflag v1.0.3
	github.com/stretchr/testify v1.3.0
	k8s.io/api v0.0.0-20190703205437-39734b2a72fe
	k8s.io/apiextensions-apiserver v0.0.0-20190704050600-357b4270afe4
	k8s.io/apimachinery v0.0.0-20190703205208-4cfb76a8bf76
	k8s.io/cli-runtime v0.0.0-20190612131021-ced92c4c4749
	k8s.io/client-go v0.0.0-20190704045512-07281898b0f0
)
