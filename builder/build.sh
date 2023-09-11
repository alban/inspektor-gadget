# This script is designed to be called by ig. Don't run it directly.
set -ux

cd "$3"

if [ "$1" = "trace_dns.bpf.c" ] ; then

	EBPF_BUILDER=ghcr.io/inspektor-gadget/inspektor-gadget-ebpf-builder
	docker run --rm \
		--name ebpf-object-builder \
		--user $(id -u):$(id -g) \
		-v $(pwd)/../..:/work \
		-v $2:/out \
		--entrypoint "/bin/bash" \
		$EBPF_BUILDER -c \
		"clang -target bpf -Wall -g -O2 -c gadgets/trace_dns/$1 \
		-I pkg/gadgets/common/ \
		-I pkg/gadgets/internal/socketenricher/bpf \
		-o /out/x86.bpf.o"
  cp $2/x86.bpf.o $2/arm64.bpf.o

else

clang -target bpf -Wall -g -O2 -D __TARGET_ARCH_x86 -c $1 \
	-I ../../pkg/amd64/ \
	-I ../../pkg/gadgets/common/ \
	-I ../../pkg/gadgets/internal/socketenricher/bpf/ \
	-o $2/x86.bpf.o

clang -target bpf -Wall -g -O2 -D __TARGET_ARCH_arm64 -c $1 \
	-I ../../pkg/arm64/ \
	-I ../../pkg/gadgets/common/ \
	-I ../../pkg/gadgets/internal/socketenricher/bpf/ \
	-o $2/arm64.bpf.o

fi
