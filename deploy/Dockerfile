# garbageman-in-a-box: builds the garbageman node with all stealth fixes
# (privkeyio/bitcoin garbageman-29.3-battle) and bundles the libre-recon watchdog.
ARG BATTLE_REPO=https://github.com/privkeyio/bitcoin
ARG BATTLE_REF=garbageman-29.3-battle

FROM debian:bookworm-slim AS build
ARG BATTLE_REPO
ARG BATTLE_REF
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates cmake build-essential pkgconf python3 \
        libevent-dev libboost-dev libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone --depth 1 --branch "$BATTLE_REF" "$BATTLE_REPO" .
RUN cmake -B build -D RDTS_CONSENT=IMPLICIT -D BUILD_GUI=OFF -D BUILD_TESTS=OFF \
        -D BUILD_BENCH=OFF -D BUILD_FUZZ_BINARY=OFF \
    && cmake --build build -j"$(nproc)" --target bitcoind bitcoin-cli \
    && strip build/bin/bitcoind build/bin/bitcoin-cli

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 libsqlite3-0 ca-certificates \
        libevent-core-2.1-7 libevent-extra-2.1-7 libevent-pthreads-2.1-7 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -m -d /home/bitcoin bitcoin
COPY --from=build /src/build/bin/bitcoind /src/build/bin/bitcoin-cli /usr/local/bin/
COPY libre_recon.py rotate.sh /opt/recon/
COPY deploy/bitcoin.conf /home/bitcoin/.bitcoin/bitcoin.conf
RUN chmod +x /opt/recon/rotate.sh && chown -R bitcoin:bitcoin /home/bitcoin
USER bitcoin
WORKDIR /home/bitcoin
EXPOSE 8333
ENTRYPOINT ["bitcoind"]
