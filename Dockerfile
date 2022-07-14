FROM alpine
ARG LUA_VER="5.4"
RUN apk add gcc make musl-dev
RUN echo  lua${LUA_VER}-dev && sleep 5
RUN apk add sqlite-dev libevent-dev libcurl curl-dev lua${LUA_VER}-dev
ADD . /build
RUN cd /build && make clean && make dev

FROM alpine
ARG LUA_VER="5.4"
RUN apk add libevent sqlite-dev sqlite tzdata libcurl lua${LUA_VER}
COPY --from=0 /build/main /main
# RUN /init_db.sh
COPY --from=0 /build/test.db /test.db
RUN cp /usr/share/zoneinfo/Europe/Moscow /etc/localtime
CMD ["/bin/sh", "-c", "/main -c /ynote.lua"]
