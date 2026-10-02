# Minimal static image — config lives on the host, not in the image.
# CA bundle required for outbound HTTPS (Google/Microsoft/…).
FROM alpine:3.21 AS certs
RUN apk add --no-cache ca-certificates

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY datanode-sso /datanode-sso
EXPOSE 8080
ENTRYPOINT ["/datanode-sso"]
