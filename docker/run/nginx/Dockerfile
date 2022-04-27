FROM alpine:3.10 as build

# Install OpenSSL
RUN apk update && \
    apk add --no-cache openssl && \
    rm -rf "/var/cache/apk/*"

RUN openssl req -newkey rsa:2048 -new -x509 \
    -subj "/C=US/ST=California/L=SanFrancisco/O=Dis/CN=www.selfsigned.com" \
    -days 1024 -nodes -out /tmp/cert.crt -keyout /tmp/cert.key

FROM nginx:1.7

COPY --from=build /tmp/cert.crt /etc/nginx/cert.crt
COPY --from=build /tmp/cert.key /etc/nginx/cert.key

COPY default.conf /etc/nginx/conf.d/default.conf

EXPOSE 443

CMD ["nginx", "-g", "daemon off;"]
