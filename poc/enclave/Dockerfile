# Multi-stage build for the signer-enclave EIF.
#
# Day 3 reproducibility fix (Finding F from Day 2):
#   - All git clones pinned to commit SHA, not floating tag
#   - Both Docker base images pinned to digest
#   - Rust toolchain version is exact (1.92.0, not "1.92" floating patch)
#   - All pins recorded in policies/build-pins.txt
#
# Stage 1 (rust-builder):
#   clux/muslrust gives us Rust 1.83 + musl-cross toolchain so our enclave
#   binary is fully static (no glibc).
#
# Stage 2 (kmstool-builder):
#   AWS aws-nitro-enclaves-sdk-c upstream sources built into the
#   kmstool_enclave_cli binary + libnsm.so. We mirror upstream
#   containers/Dockerfile.al2 essential build steps inline.
#
# Stage 3 (runtime):
#   amazonlinux:2 — same libc/openssl as the upstream kmstool image, so the
#   pre-built kmstool_enclave_cli runs without library mismatches. Our
#   static signer-enclave binary runs alongside it.
#
# To verify reproducibility:
#   1. ./scripts/build-eif.sh           # capture PCR0
#   2. sudo docker rmi signer-enclave:latest
#   3. ./scripts/build-eif.sh           # capture PCR0 again
#   4. PCR0 must match byte-for-byte
# See _hub/RUNBOOKS/signer-poc-rebuild.md for full operator runbook.

###############################################################################
# Stage 1: build our Rust enclave binary (fully static via musl).
###############################################################################
FROM clux/muslrust@sha256:b7fc8af3935272606a9682e5bbe21516744cf2f3934ce6f4d250198db3b2bd5c AS rust-builder
WORKDIR /build

# Reproducibility: pin every timestamp linker / cargo embeds.
ENV SOURCE_DATE_EPOCH=1714900000
ENV LC_ALL=C
ENV TZ=UTC

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY enclave ./enclave
COPY parent ./parent
COPY gateway ./gateway

RUN cargo build \
    --release \
    --target x86_64-unknown-linux-musl \
    --locked \
    -p signer-enclave

###############################################################################
# Stage 2: build kmstool_enclave_cli + libnsm.so from AWS upstream sources.
#
# Every source pinned to a commit SHA captured 2026-05-07 from the
# corresponding annotated tag. Tags can be force-pushed; SHAs cannot.
# All SHAs recorded in policies/build-pins.txt.
###############################################################################
FROM public.ecr.aws/amazonlinux/amazonlinux@sha256:c80c6d724a1907d0fdfe1e04f6ddff1e839311dadf19f9645646d4506bc0d2e5 AS kmstool-builder

# Pinned commit SHAs (cross-reference policies/build-pins.txt).
ARG AWS_LC_REF=cb7712dfa896d32d55992e2cb13d5fa54fb77002
ARG S2N_TLS_REF=e954ee5dc878c5c343d35574e7d07246a1e59314
ARG AWS_C_COMMON_REF=be35e65a6c67ae2ffd126516c9783ac1dd2e8910
ARG AWS_C_SDKUTILS_REF=e3c23f4aca31d9e66df25827645f72cbcbfb657a
ARG AWS_C_CAL_REF=1458c70a26877345ca28e333a092096afd410774
ARG AWS_C_IO_REF=8f4508f5ec7d2949d5545e2b1ddcd1beb47a76a8
ARG AWS_C_COMPRESSION_REF=5fab8bc5ab5321d86f6d153b06062419080820ec
ARG AWS_C_HTTP_REF=0600662610aa871a11aebe6ed67a11997317cbef
ARG AWS_C_AUTH_REF=831fa583b83574db29cbae139b42e0d7a1d1ebb8
ARG JSON_C_REF=13fede6e87d94ea9015b8d2745a235e1b02700e7
ARG AWS_NITRO_NSM_API_REF=5798fec36f49e1d199c77947f4e51f86b663750f
ARG AWS_NITRO_SDK_C_REF=4c88098890de1e371820b9e3c6bc535e69493119

# Day 4 (Finding J fix): pin yum packages by exact version-release.
# Without this, yum resolves package versions from external mutable repos
# at build time → different PCR0 on every rebuild even with image digest pin.
# Resolved versions captured 2026-05-08 via probe build; recorded in
# policies/build-pins.txt. Note "go" yum-binds to "golang" package.
RUN yum install -y \
    cmake3-3.17.5-1.amzn2 \
    gcc-7.3.1-18.amzn2 \
    git-2.47.3-1.amzn2.0.1 \
    tar-1.26-35.amzn2.0.4 \
    make-3.82-24.amzn2 \
    gcc-c++-7.3.1-18.amzn2 \
    golang-1.25.9-1.amzn2.0.1 \
    ninja-build-1.7.2-2.amzn2.0.1 \
    && yum clean all

# Rust toolchain for the libnsm crate. Exact 1.92.0, not floating "1.92".
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.92.0
ENV PATH=/root/.cargo/bin:$PATH

WORKDIR /tmp/crt-builder

# AWS C runtime stack — every clone pinned to a specific commit SHA.
RUN git clone https://github.com/awslabs/aws-lc.git aws-lc && \
    cd aws-lc && git checkout ${AWS_LC_REF} && cd .. && \
    cmake3 -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -GNinja -DBUILD_TESTING=0 -S aws-lc -B aws-lc/build && \
    go env -w GOPROXY=direct && \
    cmake3 --build aws-lc/build --parallel "$(nproc)" --target install

RUN git clone https://github.com/aws/s2n-tls.git && \
    cd s2n-tls && git checkout ${S2N_TLS_REF} && cd .. && \
    cmake3 -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -S s2n-tls -B s2n-tls/build && \
    cmake3 --build s2n-tls/build --parallel "$(nproc)" --target install

RUN git clone https://github.com/awslabs/aws-c-common.git && \
    cd aws-c-common && git checkout ${AWS_C_COMMON_REF} && cd .. && \
    cmake3 -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S aws-c-common -B aws-c-common/build && \
    cmake3 --build aws-c-common/build --parallel "$(nproc)" --target install

RUN git clone https://github.com/awslabs/aws-c-sdkutils.git && \
    cd aws-c-sdkutils && git checkout ${AWS_C_SDKUTILS_REF} && cd .. && \
    cmake3 -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S aws-c-sdkutils -B aws-c-sdkutils/build && \
    cmake3 --build aws-c-sdkutils/build --parallel "$(nproc)" --target install

RUN git clone https://github.com/awslabs/aws-c-cal.git && \
    cd aws-c-cal && git checkout ${AWS_C_CAL_REF} && cd .. && \
    cmake3 -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S aws-c-cal -B aws-c-cal/build && \
    cmake3 --build aws-c-cal/build --parallel "$(nproc)" --target install

RUN git clone https://github.com/awslabs/aws-c-io.git && \
    cd aws-c-io && git checkout ${AWS_C_IO_REF} && cd .. && \
    cmake3 -DUSE_VSOCK=1 -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S aws-c-io -B aws-c-io/build && \
    cmake3 --build aws-c-io/build --parallel "$(nproc)" --target install

RUN git clone https://github.com/awslabs/aws-c-compression.git && \
    cd aws-c-compression && git checkout ${AWS_C_COMPRESSION_REF} && cd .. && \
    cmake3 -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S aws-c-compression -B aws-c-compression/build && \
    cmake3 --build aws-c-compression/build --parallel "$(nproc)" --target install

RUN git clone https://github.com/awslabs/aws-c-http.git && \
    cd aws-c-http && git checkout ${AWS_C_HTTP_REF} && cd .. && \
    cmake3 -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S aws-c-http -B aws-c-http/build && \
    cmake3 --build aws-c-http/build --parallel "$(nproc)" --target install

RUN git clone https://github.com/awslabs/aws-c-auth.git && \
    cd aws-c-auth && git checkout ${AWS_C_AUTH_REF} && cd .. && \
    cmake3 -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S aws-c-auth -B aws-c-auth/build && \
    cmake3 --build aws-c-auth/build --parallel "$(nproc)" --target install

RUN git clone https://github.com/json-c/json-c.git && \
    cd json-c && git checkout ${JSON_C_REF} && cd .. && \
    cmake3 -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_SHARED_LIBS=OFF -GNinja -S json-c -B json-c/build && \
    cmake3 --build json-c/build --parallel "$(nproc)" --target install

# Day 5 (Phase 1 — Finding J fix): use pre-vendored nsm-api source instead
# of fresh git clone. nsm-api upstream does NOT commit Cargo.lock, so
# every clean build resolved transitive Rust crates fresh from crates.io
# → different libnsm.so → different EIF PCR0. Vendoring the deps + locking
# Cargo.lock + building --offline --locked closes the last source of
# non-determinism (Day 4 left this open).
#
# Vendor source: vendor/nsm-api/ (committed to repo).
# Generated 2026-05-10 with Rust 1.92.0 from upstream commit
# 4b851f3006c6fa98f23dcffb2cba03b39de9b8af (= tag v0.4.0 target,
# annotated-tag SHA was 5798fec3...).
COPY vendor/nsm-api /tmp/crt-builder/aws-nitro-enclaves-nsm-api
RUN cd aws-nitro-enclaves-nsm-api && \
    cargo build --release --jobs "$(nproc)" --offline --locked -p nsm-lib && \
    mv target/release/libnsm.so /usr/lib64/ && \
    mv target/release/nsm.h /usr/include/

RUN git clone https://github.com/aws/aws-nitro-enclaves-sdk-c.git && \
    cd aws-nitro-enclaves-sdk-c && git checkout ${AWS_NITRO_SDK_C_REF} && cd .. && \
    cmake3 -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -GNinja \
        -S aws-nitro-enclaves-sdk-c -B aws-nitro-enclaves-sdk-c/build && \
    cmake3 --build aws-nitro-enclaves-sdk-c/build --parallel "$(nproc)" --target install

###############################################################################
# Stage 3: minimal runtime image — amazonlinux:2 (same digest as kmstool-builder).
#
# We can't use scratch because kmstool_enclave_cli is dynamically linked
# against glibc + openssl + json-c. amazonlinux:2 already has a matching
# libc/openssl — same base AWS itself ships kmstool on.
###############################################################################
FROM public.ecr.aws/amazonlinux/amazonlinux@sha256:c80c6d724a1907d0fdfe1e04f6ddff1e839311dadf19f9645646d4506bc0d2e5 AS runtime

# Reproducibility: same env our binary baked.
ENV SOURCE_DATE_EPOCH=1714900000
ENV LC_ALL=C
ENV TZ=UTC

# kmstool-enclave-cli + its libs (libnsm.so).
# All other deps it needs (libc, libssl, libcrypto, libgcc_s, libpthread)
# are already present in amazonlinux:2.
COPY --from=kmstool-builder /usr/bin/kmstool_enclave_cli /kmstool_enclave_cli
COPY --from=kmstool-builder /usr/lib64/libnsm.so /usr/lib64/libnsm.so

# Our static signer-enclave binary.
COPY --from=rust-builder \
    /build/target/x86_64-unknown-linux-musl/release/signer-enclave \
    /signer-enclave

# Finding J FULL fix: normalize all file timestamps to SOURCE_DATE_EPOCH.
# COPY --from preserves source mtimes (= actual build wall-clock time),
# making the final image non-deterministic even when file contents are identical.
# nitro-cli build-enclave hashes the filesystem including mtimes → different PCR0.
RUN find / -exec touch -h -d @${SOURCE_DATE_EPOCH} {} + 2>/dev/null || true

ENTRYPOINT ["/signer-enclave"]
