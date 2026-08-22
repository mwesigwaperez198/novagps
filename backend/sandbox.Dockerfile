FROM alpine:3.20

RUN apk add --no-cache iproute2 coreutils bind-tools ca-certificates
USER nobody
WORKDIR /tmp
ENTRYPOINT ["/bin/sh", "-lc"]
CMD ["printf 'nova-sandbox=ready\\n'"]
