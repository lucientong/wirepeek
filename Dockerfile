FROM alpine:3.20 AS builder
RUN apk add --no-cache build-base cmake git linux-headers libpcap-dev musl-dev
WORKDIR /src
COPY . .
RUN cmake -B build \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_EXE_LINKER_FLAGS="-static" \
      -DBUILD_SHARED_LIBS=OFF \
      -DBUILD_TESTING=OFF \
    && cmake --build build -j$(nproc) \
    && strip build/src/wirepeek

FROM scratch
COPY --from=builder /src/build/src/wirepeek /wirepeek
ENTRYPOINT ["/wirepeek"]
