FROM alpine
RUN apk add gcc make musl-dev
RUN apk add sqlite-dev libevent-dev
ADD . /build
RUN cd /build && make clean && make

FROM alpine
RUN apk add libevent sqlite-dev sqlite
COPY --from=0 /build/main /main
COPY --from=0 /build/init_db.sh /init_db.sh
COPY --from=0 /build/init_db.sql /init_db.sql
RUN /init_db.sh
CMD ["/bin/sh", "-c", "/main"]