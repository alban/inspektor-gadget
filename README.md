<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="docs/images/logo/ig-logo-horizontal.svg">
    <img src="docs/images/logo/ig-logo-horizontal.svg" alt="Inspektor Gadget Logo" width="80%">
  </picture>
</h1>

[![Inspektor Gadget CI](https://github.com/inspektor-gadget/inspektor-gadget/actions/workflows/inspektor-gadget.yml/badge.svg)](https://github.com/inspektor-gadget/inspektor-gadget/actions/workflows/inspektor-gadget.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/inspektor-gadget/inspektor-gadget.svg)](https://pkg.go.dev/github.com/inspektor-gadget/inspektor-gadget)
[![Go Report Card](https://goreportcard.com/badge/github.com/inspektor-gadget/inspektor-gadget)](https://goreportcard.com/report/github.com/inspektor-gadget/inspektor-gadget)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/7962/badge)](https://www.bestpractices.dev/projects/7962)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/inspektor-gadget/inspektor-gadget/badge)](https://scorecard.dev/viewer/?uri=github.com/inspektor-gadget/inspektor-gadget)
[![Inspektor Gadget Test Reports](https://img.shields.io/badge/Link-Test%20Reports-blue)](https://inspektor-gadget.github.io/ig-test-reports)
[![Inspektor Gadget Benchmarks](https://img.shields.io/badge/Link-Benchmarks-blue)](https://inspektor-gadget.github.io/ig-benchmarks/dev/bench)
[![Release](https://img.shields.io/github/v/release/inspektor-gadget/inspektor-gadget)](https://github.com/inspektor-gadget/inspektor-gadget/releases)
[![Artifact Hub: Gadgets](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/gadgets)](https://artifacthub.io/packages/search?repo=gadgets)
[![Artifact Hub: Helm charts](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/helm-charts)](https://artifacthub.io/packages/helm/gadget/gadget)
[![Slack](https://img.shields.io/badge/slack-%23inspektor--gadget-brightgreen.svg?logo=slack)](https://kubernetes.slack.com/messages/inspektor-gadget/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/inspektor-gadget/inspektor-gadget/blob/main/LICENSE)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://github.com/inspektor-gadget/inspektor-gadget/blob/main/LICENSE-bpf.txt)

Inspektor Gadget is a set of tools and framework for data collection and system inspection on Kubernetes clusters and Linux hosts using [eBPF](https://ebpf.io/). It manages the packaging, deployment and execution of Gadgets (eBPF programs encapsulated in [OCI images](https://opencontainers.org/)) and provides mechanisms to customize and extend Gadget functionality.

**Note**: Major new functionality was released in v0.31.0. Please read the [blog post for a detailed overview](https://inspektor-gadget.io/blog/2024/08/empowering-observability_the_advent_of_image_based_gadgets).

## Features

* Build and package eBPF programs into OCI images called Gadgets
* Targets Kubernetes clusters and Linux hosts
* Collect and export data to observability tools with a simple command and via declarative configuration
* Security mechanisms to restrict and lock-down which Gadgets can be run
* Automatic [enrichment](#what-is-enrichment): map kernel data to high-level resources like Kubernetes and container runtimes
* Supports [WebAssembly](https://webassembly.org/) modules to post-process data and customize IG [operators](#what-is-an-operator); using any WASM-supported language
* Supports many modes of operation; cli, client-server, API, embeddable via Golang library

## Quick start

The following examples use the [trace_open](https://www.inspektor-gadget.io/docs/latest/gadgets/trace_open) Gadget which triggers when a file is open on the system.

### Kubernetes

#### Deployed to the Cluster

[krew](https://sigs.k8s.io/krew) is the recommended way to install
`kubectl gadget`. You can follow the
[krew's quickstart](https://krew.sigs.k8s.io/docs/user-guide/quickstart/)
to install it and then install `kubectl gadget` by executing the following
commands.

```bash
kubectl krew install gadget
kubectl gadget deploy
kubectl gadget run trace_open:latest
```

Check [Installing on Kubernetes](https://www.inspektor-gadget.io/docs/latest/reference/install-kubernetes) to learn more about different options.

`kubectl-gadget` is also packaged for the following distributions:

[![`kubectl-gadget`](https://repology.org/badge/vertical-allrepos/kubectl-gadget.svg)](https://repology.org/project/kubectl-gadget/versions)

### Kubectl Node Debug

We can use [kubectl node debug](https://kubernetes.io/docs/tasks/debug/debug-cluster/kubectl-node-debug/) to run `ig` on a Kubernetes node:

```bash
kubectl debug --profile=sysadmin node/minikube-docker -ti --image=ghcr.io/inspektor-gadget/ig:latest -- ig run trace_open:latest
```

For more information on how to use `ig` without installation on Kubernetes, please refer to the [ig documentation](https://www.inspektor-gadget.io/docs/latest/reference/ig#using-ig-with-kubectl-debug-node).

### Linux

#### Install Locally

Install the `ig` binary locally on Linux and run a Gadget:

```bash
IG_ARCH=amd64
IG_VERSION=$(curl -s https://api.github.com/repos/inspektor-gadget/inspektor-gadget/releases/latest | jq -r .tag_name)

curl -sL https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${IG_VERSION}/ig-linux-${IG_ARCH}-${IG_VERSION}.tar.gz | sudo tar -C /usr/local/bin -xzf - ig

sudo ig run trace_open:latest
```

Check [Installing on Linux](https://www.inspektor-gadget.io/docs/latest/reference/install-linux) to learn more.

`ig` is also packaged for the following distributions:

[![`ig`](https://repology.org/badge/vertical-allrepos/inspektor-gadget.svg)](https://repology.org/project/inspektor-gadget/versions)

#### Run in a Container

```bash
docker run -ti --rm --privileged -v /:/host --pid=host ghcr.io/inspektor-gadget/ig:latest run trace_open:latest
```

For more information on how to use `ig` without installation on Linux, please check [Using ig in a container](https://www.inspektor-gadget.io/docs/latest/reference/ig#using-ig-in-a-container).

### MacOS or Windows

It's possible to control an `ig` running in Linux from different operating systems by using the `gadgetctl` binary.

Run the following on a Linux machine to make `ig` available to clients.

```bash
sudo ig daemon --host=tcp://0.0.0.0:1234
```

Download the `gadgetctl` tools for MacOS
([amd64](https://github.com/inspektor-gadget/inspektor-gadget/releases/download/v0.30.0/gadgetctl-darwin-amd64-v0.30.0.tar.gz),
[arm64](https://github.com/inspektor-gadget/inspektor-gadget/releases/download/v0.30.0/gadgetctl-darwin-arm64-v0.30.0.tar.gz)) or [windows](https://github.com/inspektor-gadget/inspektor-gadget/releases/download/v0.30.0/gadgetctl-windows-amd64-v0.30.0.tar.gz) and run the Gadget specifying the IP address of the Linux machine:


```bash
gadgetctl run trace_open:latest --remote-address=tcp://$IP:1234
```

***The above demonstrates the simplest command. To learn how to filter, export, etc. please consult the documentation for the [run](https://www.inspektor-gadget.io/docs/latest/reference/run) command***.

## Core concepts

### What is a Gadget?

Gadgets are the central component in the Inspektor Gadget framework. A Gadget is an [OCI image](https://opencontainers.org/) that includes one or more eBPF programs, metadata YAML file and, optionally, WASM modules for post processing.
As OCI images, they can be stored in a container registry (compliant with the OCI specifications), making them easy to distribute and share.
Gadgets are built using the [`ig image build`](https://www.inspektor-gadget.io/docs/latest/gadget-devel/building) command.

You can find a growing collection of Gadgets on [Artifact HUB](https://artifacthub.io/packages/search?kind=22). This includes both in-tree Gadgets (hosted in this git repository in the [/gadgets](./gadgets/README.md) directory and third-party Gadgets).

See the [Gadget documentation](https://www.inspektor-gadget.io/docs/latest/gadgets/) for more information.

### What is enrichment?

The data that eBPF collects from the kernel includes no knowledge about Kubernetes, container
runtimes or any other high-level user-space concepts. In order to relate this data to these high-level
concepts and make the eBPF data immediately more understandable, Inspektor Gadget automatically
uses kernel primitives such as mount namespaces, pids or similar to infer which high-level
concepts they relate to; Kubernetes pods, container names, DNS names, etc. The process of augmenting
the eBPF data with these high-level concepts is called *enrichment*.

Enrichment flows the other way, too. Inspektor Gadget enables users to do high-performance
in-kernel filtering by only referencing high-level concepts such as Kubernetes pods, container
names, etc.; automatically translating these to the corresponding low-level kernel resources.

### What is an operator?

In Inspektor Gadget, an operator is any part of the framework where an action is taken. Some operators are under-the-hood (i.e. fetching and loading Gadgets) while others are user-exposed (enrichment, filtering, export, etc.) and can be reordered and overridden.

### Further learning

Use the [project documentation](https://www.inspektor-gadget.io/docs/latest/) to learn more about:

* [Reference](https://www.inspektor-gadget.io/docs/latest/reference)
* [Gadgets](https://www.inspektor-gadget.io/docs/latest/gadgets)
* [Contributing](https://www.inspektor-gadget.io/docs/latest/devel/contributing/)

## Kernel requirements

Kernel requirements are largely determined by the specific eBPF functionality a Gadget makes use of.
The eBPF functionality available to Gadgets depend on the version and configuration of the kernel running
in the node/machine where the Gadget is being loaded. Gadgets developed by the Inspektor
Gadget project require at least Linux 5.10 with [BTF](https://www.kernel.org/doc/html/latest/bpf/btf.html) enabled.

Refer to the [documentation for a specific Gadget](https://www.inspektor-gadget.io/docs/latest/gadgets) for any notes regarding requirements.

## Code examples

There are some examples in [this](./examples/) folder showing the usage
of the Golang packages provided by Inspektor Gadget. These examples are
designed for developers that want to use the Golang packages exposed by
Inspektor Gadget directly. End-users do not need this and can use
`kubectl-gadget` or `ig` directly.

## Security features

Inspektor Gadget offers security features which are described in the following document:

* [Verify assets](https://inspektor-gadget.io/docs/latest/reference/verify-assets): Covers everything with regard to signing and verifying of images and release assets. It also showcases the different SBOMs we generate like the [`ig`](https://github.com/inspektor-gadget/inspektor-gadget/releases/download/v0.38.0/ig-linux-amd64-v0.38.0.bom.json) one.
* [Restricting Gadgets](https://inspektor-gadget.io/docs/latest/reference/restricting-gadgets): Details how users can restrict which gadgets can be run based on different filters.

## Contributing

Contributions are welcome, see [CONTRIBUTING](docs/devel/contributing.md).

## Community Meeting

We hold community meetings regularly. Please check our [calendar](https://calendar.google.com/calendar/u/0/embed?src=ac93fb85a1999d57dd97cce129479bb2741946e1d7f4db918fe14433c192152d@group.calendar.google.com)
for the full schedule of up-coming meetings and please add any topic you want to discuss to our [meeting
notes](https://docs.google.com/document/d/1cbPYvYTsdRXd41PEDcwC89IZbcA8WneNt34oiu5s9VA/edit)
document.

## Slack

Join the discussions on the [`#inspektor-gadget`](https://kubernetes.slack.com/messages/inspektor-gadget/) channel in the Kubernetes Slack.

## Recent Videos

- Talk: [Demystifying DNS: A Guide to Understanding and Debugging Request Flows in Kubernetes Clusters, Container Days Hamburg - September 2024](https://www.youtube.com/watch?v=KQpZg_NqbZw)
- Talk: [eBPF Data Collection for Everyone – empowering the community to obtain Linux insights using Inspektor Gadget](https://www.youtube.com/watch?v=tkKXdaqji9c)
- Talk: [Collecting Low-Level Metrics with eBPF, KubeCon + CloudNativeCon North America 2023](https://kccncna2023.sched.com/event/a70c0a016973beb5705f5f72fa58f622) ([video](https://www.youtube.com/watch?v=_ft3iTw5uv8), [slides](https://static.sched.com/hosted_files/kccncna2023/91/Collecting%20Low-Level%20Metrics%20with%20eBPF.pdf))
- Interview: [Kubernetes Security and Troubleshooting Multitool: Inspektor Gadget](https://www.youtube.com/watch?v=0GDYDYhPPRw)
- Interview: [Enlightning - Go Go Gadget! Inspektor Gadget and Observability](https://www.youtube.com/watch?v=Io6vqHitTzQ)
- Presentation: [Misc - Feat. Kepler, Inspektor Gadget, k8sgpt, Perses, and Pixie (You Choose!, Ch. 04, Ep. 09)](https://youtu.be/OZE1hoT9-gs?t=1267)

## Thanks

* [BPF Compiler Collection (BCC)](https://github.com/iovisor/bcc): some of the gadgets are based on BCC tools.
* [kubectl-trace](https://github.com/iovisor/kubectl-trace): the Inspektor Gadget architecture was inspired from kubectl-trace.
* [cilium/ebpf](https://github.com/cilium/ebpf): the gadget tracer manager and some other gadgets use the cilium/ebpf library.

## License

The Inspektor Gadget user-space components are licensed under the
[Apache License, Version 2.0](LICENSE). The BPF code templates are licensed
under the [General Public License, Version 2.0, with the Linux-syscall-note](LICENSE-bpf.txt).
