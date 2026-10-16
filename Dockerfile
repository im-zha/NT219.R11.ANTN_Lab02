# Build with either: docker build -t aes-lab .  OR  podman build -t aes-lab .
# Override CMD with /opt/aes/bin/AES, or with:
# python3 /opt/aes/share/AESModes/python/demo.py /opt/aes/lib/libaes_modes.so
FROM docker.io/library/debian:bookworm-slim AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends g++ cmake make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY CMakeLists.txt AES.cpp ./
COPY modes/ ./modes/
COPY examples/python/ ./examples/python/

RUN cmake -S . -B /build \
        -DCMAKE_BUILD_TYPE=Release \
        -DAES_LIBRARY_TYPE=BOTH \
        -DAES_WARNINGS_AS_ERRORS=ON \
        -DCMAKE_INSTALL_PREFIX=/opt/aes \
        -DCMAKE_INSTALL_LIBDIR=lib \
    && cmake --build /build --parallel 2 \
    && ctest --test-dir /build --output-on-failure \
    && cmake --install /build

FROM docker.io/library/debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/aes/ /opt/aes/
ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /opt/aes
USER 65532:65532
CMD ["/opt/aes/bin/aes_tests"]
