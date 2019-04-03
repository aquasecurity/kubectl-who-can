# kubectl-who-can
[WIP] show who has permissions to &lt;verb> &lt;resources> in kubernetes

[![asciicast](https://asciinema.org/a/ccqqYwA5L5rMV9kd1tgzyZJ2j.svg)](https://asciinema.org/a/ccqqYwA5L5rMV9kd1tgzyZJ2j)

## Installation

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
go get -v github.com/aquasecurity/kubectl-who-can
```
The `kubectl-who-can` binary will be in `$GOPATH/bin`.

Option 3 (if you don't have a Go compiler, but have Docker installed):
```
docker run --rm -v /usr/local/bin:/go/bin golang go get -v github.com/aquasecurity/kubectl-who-can
```
The `kubectl-who-can` binary will be in `/usr/local/bin`.

## TODO

* Filter by namespace
* Specify a particular object e.g. who-can use pod-security-policy \<name\>
* Make it a kubectl plugin (for now it's a standalone executable)
* Alert if user doesn't have access to all namespaces, roles, clusterroles or bindings (as info won't be complete)
