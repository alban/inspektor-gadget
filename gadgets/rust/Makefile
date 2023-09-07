build:
	docker build -t albanc/rust-wasm-builder .
	CONTAINER_ID=$(shell docker create albanc/rust-wasm-builder) && \
		docker cp $$CONTAINER_ID:/src/pkg/trace_dns_bg.wasm ./trace_dns_rust.wasm && \
		docker rm $$CONTAINER_ID


