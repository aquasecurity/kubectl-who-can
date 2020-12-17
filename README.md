[![GitHub Release][release-img]][release]
[![GitHub Action][build-action-img]][build-action]
[![Coverage Status][cov-img]][cov]
[![Go Report Card][report-card-img]][report-card]
[![License][license-img]][license]
[![GitHub All Releases][github-all-releases-img]][release]

# kubectl-who-can

Shows which subjects have RBAC permissions to VERB [TYPE | TYPE/NAME | NONRESOURCEURL] in Kubernetes.

[![asciicast][asciicast-img]][asciicast]

## Installation

There are several ways to install `kubectl-who-can`. The recommended installation is via the `kubectl` plugin manager
called [`krew`](https://github.com/kubernetes-sigs/krew).

### krew

I assume that you've already [installed](https://github.com/kubernetes-sigs/krew#installation) `krew`. Then run the following command:

```
kubectl krew install who-can
```

The plugin will be available as `kubectl who-can`.

### Manual

Download a [release distribution archive][release] for your operating system, extract it, and add the `kubectl-who-can`
executable to your `$PATH`. For example, to manually install `kubectl-who-can` on macOS run the following command:

```
VERSION=`git describe --abbrev=0`

mkdir -p /tmp/who-can/$VERSION && \
curl -L https://github.com/aquasecurity/kubectl-who-can/releases/download/$VERSION/kubectl-who-can_darwin_x86_64.tar.gz \
  | tar xz -C /tmp/who-can/$VERSION && \
sudo mv -i /tmp/who-can/$VERSION/kubectl-who-can /usr/local/bin
```

## Build from Source

This is a standard Go program. If you already know how to build
and install Go code, you probably won't need these instructions.

Note that while the code is small, it has some rather big
dependencies, and fetching + building these dependencies can
take a few minutes.

Option 1 (if you have a Go compiler and want to tweak the code):
```bash
# Clone this repository (or your fork)
git clone https://github.com/aquasecurity/kubectl-who-can
cd kubectl-who-can
make
```
The `kubectl-who-can` binary will be in the current directory.

Option 2 (if you have a Go compiler and just want the binary):
```
go get -v github.com/aquasecurity/kubectl-who-can/cmd/kubectl-who-can
```
The `kubectl-who-can` binary will be in `$GOPATH/bin`.

Option 3 (if you don't have a Go compiler, but have Docker installed):
```
docker run --rm -v /usr/local/bin:/go/bin golang go get -v github.com/aquasecurity/kubectl-who-can/cmd/kubectl-who-can
```
The `kubectl-who-can` binary will be in `/usr/local/bin`.

## Usage

`$ kubectl who-can VERB (TYPE | TYPE/NAME | NONRESOURCEURL) [flags]`

### Flags

Name             | Shorthand | Default | Usage
-----------------|-----------|---------|----------------------------
namespace        | n         |         | If present, the namespace scope for this CLI request
all-namespaces   | A         | false   | If true, check for users that can do the specified action in any of the available namespaces
subresource      |           |         | Specify a sub-resource such as pod/log or deployment/scale

For additional details on flags and usage, run `kubectl who-can --help`.

[release-img]: https://img.shields.io/github/release/aquasecurity/kubectl-who-can.svg?logo=github
[release]: https://github.com/aquasecurity/kubectl-who-can/releases

[build-action-img]: https://github.com/aquasecurity/kubectl-who-can/workflows/build/badge.svg
[build-action]: https://github.com/aquasecurity/kubectl-who-can/actions

[cov-img]: https://codecov.io/github/aquasecurity/kubectl-who-can/branch/main/graph/badge.svg
[cov]: https://codecov.io/github/aquasecurity/kubectl-who-can

[report-card-img]: https://goreportcard.com/badge/github.com/aquasecurity/kubectl-who-can
[report-card]: https://goreportcard.com/report/github.com/aquasecurity/kubectl-who-can

[license-img]: https://img.shields.io/github/license/aquasecurity/kubectl-who-can.svg
[license]: https://github.com/aquasecurity/kubectl-who-can/blob/main/LICENSE
[github-all-releases-img]: https://img.shields.io/github/downloads/aquasecurity/kubectl-who-can/total?logo=github

[asciicast-img]: https://asciinema.org/a/ccqqYwA5L5rMV9kd1tgzyZJ2j.svg
[asciicast]: https://asciinema.org/a/ccqqYwA5L5rMV9kd1tgzyZJ2j
