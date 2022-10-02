FROM alpine
ARG LUA_VER="5.4"
RUN apk add gcc make musl-dev rust cargo clang
RUN echo  lua${LUA_VER}-dev && sleep 5
RUN apk add sqlite-dev libevent-dev libcurl curl-dev lua${LUA_VER}-dev libmicrohttpd libmicrohttpd-dev
ADD . /build
RUN cd /build && make clean && make dev
RUN cd /build && cargo build --release

FROM alpine
ARG LUA_VER="5.4"
RUN apk add libevent sqlite-dev sqlite tzdata libcurl lua${LUA_VER} libmicrohttpd
COPY --from=0 /build/main /main
COPY --from=0 /build/target/release/ynote /ynote
# RUN /init_db.sh
COPY --from=0 /build/test.db /test.db
RUN cp /usr/share/zoneinfo/Europe/Moscow /etc/localtime
CMD ["/bin/sh", "-c", "/main -c /ynote.lua"]
