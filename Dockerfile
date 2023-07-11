#syntax=docker/dockerfile:labs
FROM debian
RUN <<EOF
rm -f /etc/apt/apt.conf.d/docker-clean
echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache
EOF

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,target=/var/lib/apt,sharing=locked <<EOF
echo 'deb http://cloudfront.debian.net/debian sid main' >> /etc/apt/sources.list
apt-get update
apt-get upgrade
apt-get install -y --no-install-recommends libbpf-dev clang llvm make netcat vim
rm -rf /var/lib/apt/lists/*
EOF

RUN --mount=type=bind,target=build <<EOF
  cd /build
  make
EOF
COPY . build
CMD mount -t debugfs debugfs /sys/kernel/debug && sleep inf
