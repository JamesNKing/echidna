### Dockerfile for the echidna rootkit payload
# Note: Invoke this Dockerfile from the `Payload_Type/echidna` directory using the command
#   `docker build -t docker.io/youruser/echidna:v1.0.0 -f .docker/Dockerfile .`
FROM docker.io/library/fedora:39

# Version of sccache to install
ENV SCCACHE_VERSION v0.7.6

# Install packages for rootkit development
RUN dnf install -y \
        python3.11 \
        python3-pip \
        python3.11-devel \
        gcc \
        clang \
        make \
        curl \
        musl-gcc \
        musl-libc-static \
        glibc-devel \
        glibc-devel.i686 \
        libgcc.i686 \
        libatomic-static.i686 \
        libatomic.i686 \
        openssl-devel \
        openssl-devel.i686 \
        perl-FindBin \
        perl-File-Compare \
        perl-IPC-Cmd \
        perl-File-Copy \
        perl-lib \
        && dnf clean all

RUN python3.11 -m ensurepip

WORKDIR /tmp

# Install the python dependencies
COPY requirements.txt .
RUN python3.11 -m pip install -r requirements.txt

RUN rm requirements.txt

# Install rust with Linux targets only (no Windows cross-compilation needed)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o rustup.sh \
    && sh rustup.sh -y \
        --profile minimal \
        --default-toolchain stable \
        -t x86_64-unknown-linux-gnu \
        -t i686-unknown-linux-gnu \
        -t x86_64-unknown-linux-musl

RUN rm -f rustup.sh

ENV PATH=$PATH:/root/.cargo/bin

# Install sccache
RUN curl -L \
    "https://github.com/mozilla/sccache/releases/download/${SCCACHE_VERSION}/sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
    -o sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl.tar.gz
RUN tar xf sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl.tar.gz
RUN mv sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl/sccache /usr/bin/sccache
RUN chmod +x /usr/bin/sccache
RUN rm -rf sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl
RUN rm -f sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl.tar.gz

WORKDIR /Mythic
COPY main.py main.py
COPY echidna echidna

# Fetch dependencies
WORKDIR /Mythic/echidna/agent_code
RUN cargo fetch

WORKDIR /Mythic

COPY .docker/config.toml /root/.cargo/config.toml
ENV SCCACHE_DIR /Mythic/.cache/sccache
CMD ["python3.11", "main.py"]