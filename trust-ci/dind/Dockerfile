FROM docker:29.10.1-dind-rootless@sha256:a35dc0ba082450cbb4d372f2decb416eb71676b4788fbebdb10d1cd70fb9edae
USER root
RUN rm -f /usr/local/bin/docker \
    && mkdir -p /api /var/lib/trust-ci-transfer \
    && chown 1000:1000 /api && chmod 0750 /api \
    && chown 10001:10001 /var/lib/trust-ci-transfer
USER rootless
