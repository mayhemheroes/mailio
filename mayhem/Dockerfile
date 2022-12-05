# Build Stage
FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y cmake clang libboost-all-dev libssl-dev

ADD . /mailio
WORKDIR /mailio

RUN mkdir build
WORKDIR build

RUN CC=clang CXX=clang++ cmake -DBUILD_FUZZ_TARGETS=ON ..
RUN make -j$(nproc) all

RUN mkdir fuzz_binaries && find fuzz -executable -type f | xargs cp -t fuzz_binaries

# Package Stage
FROM --platform=linux/amd64 ubuntu:20.04

RUN apt-get update &&  \
    DEBIAN_FRONTEND=noninteractive apt-get install -y libboost-all-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /mailio/build/fuzz_binaries  /fuzz_binaries/