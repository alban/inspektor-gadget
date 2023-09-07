FROM fedora
RUN dnf install -y which
 # cargo rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y
RUN export PATH="$HOME/.cargo/bin:$PATH" ; \
	curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | bash -s -- -y

#RUN cargo install wasm-pack
RUN mkdir -p /src/src
WORKDIR /src
COPY Cargo.toml /src/Cargo.toml
COPY trace_dns.rs /src/src/lib.rs
RUN dnf install -y gcc
RUN export PATH="$HOME/.cargo/bin:$PATH" ; \
	/root/.cargo/bin/wasm-pack build --target web
