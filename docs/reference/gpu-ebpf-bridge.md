---
title: gpu-ebpf-bridge
sidebar_position: 900
description: >
  Deploy the gpu-ebpf-bridge daemon alongside Inspektor Gadget to
  expose per-device and per-process GPU telemetry to consumer
  gadgets.
---

The `gpu-ebpf-bridge` daemon polls NVIDIA GPU telemetry via NVML and
publishes it through four bpffs-pinned BPF maps that consumer
gadgets read from. Gadgets can then enrich kernel-side events
(kprobes, uprobes, tracepoints) with per-process or per-device GPU
context in one hash lookup at event emit time.

See the design document [`004-gpu-telemetry-enricher`][design] for
the architecture and the command-line reference in
[`cmd/gpu-ebpf-bridge/README.md`][cli] for flags and internals.
This page focuses on deployment.

[design]: https://github.com/inspektor-gadget/inspektor-gadget/blob/main/docs/design/004-gpu-telemetry-enricher.md
[cli]: https://github.com/inspektor-gadget/inspektor-gadget/blob/main/cmd/gpu-ebpf-bridge/README.md

## Requirements

- NVIDIA GPU with driver **>= 545** (CUDA 12.3, October 2023) or newer.
- Kernel **>= 5.8** (for `BPF_MAP_TYPE_LRU_HASH` and
  `bpf_iter/bpf_map_elem`, used by the maps and by consumer gadgets).
- Access to `/sys/fs/bpf` inside the bridge container (bpffs must be
  mounted; the bridge is typically deployed alongside IG, which
  already mounts it).
- `libnvidia-ml.so.1` from the NVIDIA driver, available inside the
  bridge container at runtime. Bind-mounted from the host; the
  container image itself does not ship NVIDIA libraries. See the
  per-mode setup below.

## Kubernetes: helm chart (recommended)

Enable the bridge as a sidecar in the existing IG DaemonSet via a
single helm value:

```yaml
# values.yaml
gpu:
  enabled: true
```

By default (`accessMode: toolkit-env`) the sidecar sets the two
NVIDIA Container Toolkit environment variables that trigger the
`runc` prestart hook to bind-mount libnvidia-ml.so.1 and grant
`/dev/nvidia*` access, without reserving a GPU for scheduling.

When `gpu.enabled` is true, the IG pod's nodeSelector is merged with
`gpu.nodeSelector` (default: `nvidia.com/gpu.present: "true"`), so
the whole IG pod runs only on GPU-labelled nodes. Override with
`gpu.nodeSelector: {}` if you want IG to run on all nodes.

Three deployment modes are supported to match your cluster's setup:

### `toolkit-env` (default)

Works on clusters where the NVIDIA Container Toolkit is installed
and `nvidia-container-runtime` is the default container runtime:

- Vanilla Kubernetes with the [NVIDIA GPU Operator](https://github.com/NVIDIA/gpu-operator)
- Google GKE with cos_containerd GPU nodes
- Red Hat OpenShift with the NVIDIA GPU Operator
- AKS clusters where the GPU Operator has been installed on top of
  the default node pool

Same setting used by [DCGM Exporter][dcgm]. Does not reserve any GPU;
telemetry-only.

[dcgm]: https://github.com/NVIDIA/dcgm-exporter

### `hostpath`

Fallback for clusters where the toolkit-env approach fails, most
notably **AKS default GPU node pools** (Microsoft's default
nvidia-device-plugin denies `NVIDIA_VISIBLE_DEVICES` from
non-`nvidia.com/gpu`-requesting pods as a security precaution).

Explicitly HostPath-mounts `/dev/nvidiactl`, `/dev/nvidia0`,
`/dev/nvidia-uvm`, and `libnvidia-ml.so.1` from the host:

```yaml
gpu:
  enabled: true
  accessMode: hostpath
  hostpath:
    # Distro-dependent library path:
    #   /usr/lib/x86_64-linux-gnu  Debian, Ubuntu, AKS Ubuntu, GKE COS
    #   /usr/lib64                 RHEL, Fedora, CentOS, OpenShift
    nvidiaLibsPath: /usr/lib/x86_64-linux-gnu
```

Works on any cluster with an NVIDIA driver installed on the host,
regardless of the container runtime configuration.

### `device-plugin`

**Not recommended** for fleet-wide telemetry. Requests
`nvidia.com/gpu: 1` in the sidecar's `resources.limits`, which
reserves a full GPU per node for the bridge. Only useful if you have
MIG partitioning with a dedicated telemetry partition:

```yaml
gpu:
  enabled: true
  accessMode: device-plugin
```

### `kubectl gadget deploy`

`kubectl gadget deploy` currently uses a pre-rendered manifest
(`pkg/resources/manifests/deploy.yaml`) generated from this helm
chart with default values (`gpu.enabled=false`), so it does **not**
deploy the bridge. Use `helm install ... --set gpu.enabled=true`
above instead.

Once [issue #5592][5592] (migrating `kubectl gadget deploy` to use
the helm chart directly) is resolved, `kubectl gadget deploy` will
support `gpu.enabled=true` transparently with no additional work.

[5592]: https://github.com/inspektor-gadget/inspektor-gadget/issues/5592

## Kubernetes: `kubectl debug node`

For one-shot ad-hoc use without a cluster-wide install, run the
bridge in one `kubectl debug node` invocation and the gadget in
another:

```bash
# Terminal 1: start the bridge on the target node.
kubectl debug --profile=sysadmin node/mynode -ti \
        --image=ghcr.io/inspektor-gadget/gpu-ebpf-bridge:latest \
        -- gpu-ebpf-bridge --mode=real --keep-pins=true

# Terminal 2: run a GPU-consuming gadget on the same node.
kubectl debug --profile=sysadmin node/mynode -ti \
        --image=ghcr.io/inspektor-gadget/ig:latest \
        -- ig run <gadget-image>
```

Both `kubectl debug node` containers share `/sys/fs/bpf` under
`--profile=sysadmin`, so the maps published by the bridge are
visible to `ig` in the second container.

## Linux (no Kubernetes)

Run the bridge as a background process before starting a gadget:

```bash
sudo gpu-ebpf-bridge --mode=real --keep-pins=true &
sudo ig run <gadget-image>
```

`--keep-pins=true` leaves the four maps in bpffs after the bridge
exits, so a subsequent `ig run` still sees the (now stale) data;
drop the flag to have the maps disappear on bridge shutdown.

## `ig` in a container

Run the bridge and `ig` as sibling containers, both sharing
`/sys/fs/bpf`:

```bash
docker run -d --rm --name gpu-ebpf-bridge --privileged --gpus all \
        -v /sys/fs/bpf:/sys/fs/bpf \
        ghcr.io/inspektor-gadget/gpu-ebpf-bridge:latest

docker run -ti --rm --privileged --pid=host \
        -v /:/host -v /sys/fs/bpf:/sys/fs/bpf \
        ghcr.io/inspektor-gadget/ig:latest run <gadget-image>
```

`--gpus all` triggers the NVIDIA Container Toolkit hook on the
bridge container only; the ig container does not need GPU access.

## Verifying the deployment

Once the bridge is running, check the maps are being populated:

```bash
# Inside a container that shares /sys/fs/bpf with the bridge:
sudo gpu-ebpf-bridge --dump
```

Expect one entry per active GPU under `gpu_device`, and per-PID
entries under `gpu_per_pid` and `gpu_per_pid_per_device` once a
CUDA workload starts.

## Non-GPU nodes

On nodes without an NVIDIA driver, the bridge exits at startup with
`ErrNotAvailable`. When deployed via helm with `gpu.enabled=true`
and the default `gpu.nodeSelector: nvidia.com/gpu.present=true`,
non-GPU nodes are skipped entirely — the whole IG pod is only
scheduled where the nodeSelector matches. Set `gpu.nodeSelector: {}`
if you want IG on all nodes and can accept the bridge sidecar
crashing (and being restarted) on non-GPU nodes.
