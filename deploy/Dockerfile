# ---- build stage: ISA-L + BLAKE3 + the pybind11 extension (vault_native) ----
FROM python:3.12-slim-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build git pkg-config nasm autoconf automake libtool \
    && rm -rf /var/lib/apt/lists/*
# ISA-L from source (distro packages are often old)
RUN git clone --depth 1 --branch v2.31.0 https://github.com/intel/isa-l.git /tmp/isa-l \
    && cd /tmp/isa-l && ./autogen.sh && ./configure --prefix=/usr/local \
    && make -j"$(nproc)" && make install && ldconfig
WORKDIR /src
COPY pyproject.toml ./
COPY native native
# BLAKE3 C sources are compiled into the extension
RUN git clone --depth 1 --branch 1.5.4 https://github.com/BLAKE3-team/BLAKE3.git native/third_party/BLAKE3
COPY vault vault
RUN pip install --no-cache-dir "scikit-build-core>=0.9" "pybind11>=2.12" \
    && pip wheel --no-cache-dir --no-build-isolation -w /wheels .

# ---- runtime stage ----
FROM python:3.12-slim-bookworm
# iproute2/iptables let chaos tests inject network faults (run with cap_add: [NET_ADMIN])
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/lib/libisal.so* /usr/local/lib/
RUN ldconfig
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl uvloop && rm -rf /wheels \
    && python -c "import vault.cluster_rpc.proto, vault_native; print('native core OK')"
ENV PYTHONUNBUFFERED=1 VAULT_DRIVES=/data/disk{1...4} VAULT_QUEUE_DIR=/var/lib/vault/queues
RUN mkdir -p /var/lib/vault/queues /var/log/vault
EXPOSE 9000 9100
HEALTHCHECK --interval=10s --timeout=3s --start-period=60s CMD curl -fs http://localhost:9000/vault/health/live || exit 1
ENTRYPOINT ["python", "-m", "vault.main"]
