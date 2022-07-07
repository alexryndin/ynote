FROM alpine
RUN apk add gcc make musl-dev
RUN apk add sqlite-dev libevent-dev libcurl curl-dev
ADD . /build
RUN cd /build && make clean && make

FROM alpine
RUN apk add libevent sqlite-dev sqlite tzdata libcurl
COPY --from=0 /build/main /main
COPY --from=0 /build/ynote_prod.json /ynote.json
# RUN /init_db.sh
COPY --from=0 /build/test.db /test.db
RUN cp /usr/share/zoneinfo/Europe/Moscow /etc/localtime
CMD ["/bin/sh", "-c", "/main /main.db"]
