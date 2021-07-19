# Prepare and build gadget artifacts in a container
ARG OS_TAG=20.04
FROM ubuntu:${OS_TAG} as builder

RUN set -ex; \
	export DEBIAN_FRONTEND=noninteractive; \
	apt-get update && \
	apt-get install -y gcc make golang-1.16 ca-certificates git clang \
		software-properties-common && \
	add-apt-repository -y ppa:tuxinvader/kernel-build-tools && \
	apt-get update && \
	apt-get install -y libbpf-dev && \
	ln -s /usr/lib/go-1.16/bin/go /bin/go


# Cache go modules so they won't be downloaded at each build
COPY go.mod go.sum /gadget/
RUN cd /gadget && go mod download

# This COPY is limited by .dockerignore
COPY ./ /gadget
RUN cd /gadget/gadget-container && make gadget-container-deps

# Builder: traceloop

# traceloop built from:
# https://github.com/kinvolk/traceloop/commit/3a57301aba445720c630ba99b58892da72a31e35
# See:
# - https://github.com/kinvolk/traceloop/actions
# - https://hub.docker.com/r/kinvolk/traceloop/tags

FROM docker.io/kinvolk/traceloop:202006050210553a5730 as traceloop

# Main gadget image

# BCC built from:
# https://github.com/kinvolk/bcc/commit/6ed81423f8b493aab15bd22c6930ef913102d758
# See BCC section in docs/CONTRIBUTING.md for further details.

FROM quay.io/kinvolk/bcc:6ed81423f8b493aab15bd22c6930ef913102d758-focal-release

RUN set -ex; \
	export DEBIAN_FRONTEND=noninteractive; \
	apt-get update && \
	apt-get install -y --no-install-recommends \
		ca-certificates curl jq && \
        rmdir /usr/src && ln -sf /host/usr/src /usr/src && \
	pip install grpcio grpcio-tools

COPY gadget-container/entrypoint.sh gadget-container/cleanup.sh /

COPY --from=builder /gadget/gadget-container/bin/gadgettracermanager /bin/
COPY --from=builder /gadget/gadget-container/bin/networkpolicyadvisor /bin/

COPY gadget-container/gadgets/bcck8s /opt/bcck8s/

# TODO: This should be a python package
COPY pkg/gadgettracermanager/api/gadgettracermanager_pb2.py /usr/share/bcc/tools/
COPY pkg/gadgettracermanager/api/gadgettracermanager_pb2_grpc.py /usr/share/bcc/tools/

COPY --from=traceloop /bin/traceloop /bin/

## Hooks Begins

# OCI
COPY gadget-container/hooks/oci/prestart.sh gadget-container/hooks/oci/poststop.sh /opt/hooks/oci/
COPY --from=builder /gadget/gadget-container/bin/ocihookgadget /opt/hooks/oci/

# runc
COPY --from=builder /gadget/gadget-container/bin/runchooks.so /opt/hooks/runc/
COPY gadget-container/hooks/runc/add-hooks.jq /opt/hooks/runc/

# cri-o
COPY gadget-container/hooks/crio/gadget-prestart.json gadget-container/hooks/crio/gadget-poststop.json /opt/hooks/crio/

# nri
COPY --from=builder /gadget/gadget-container/bin/nrigadget /opt/hooks/nri/
COPY gadget-container/hooks/nri/conf.json /opt/hooks/nri/

## Hooks Ends
