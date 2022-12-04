FROM alpine
ARG LUA_VER="5.4"
RUN apk add gcc make musl-dev
RUN echo  lua${LUA_VER}-dev && sleep 5
RUN apk add sqlite-dev libevent-dev libcurl curl-dev lua${LUA_VER}-dev libmicrohttpd libmicrohttpd-dev
ADD . /build
RUN cd /build && make clean && make dev

FROM alpine
ARG LUA_VER="5.4"
RUN apk add libevent sqlite-dev sqlite tzdata libcurl lua${LUA_VER} lua${LUA_VER}-dev libmicrohttpd wget make
RUN mkdir /luarocks
RUN cd /luarocks                                                    \
       && wget https://luarocks.org/releases/luarocks-3.9.1.tar.gz  \
       && tar zxpf luarocks-3.9.1.tar.gz                            \
       && cd luarocks-3.9.1                                         \
       && ./configure --with-lua-include=/usr/include               \
       && (make || true)                                            \
       && ./luarocks config variables.LUA_INCDIR /usr/include/lua5.4\
       && ./luarocks --tree /usr install lua-resty-template

COPY --from=0 /build/main /main
# RUN /init_db.sh
COPY --from=0 /build/test.db /test.db
COPY --from=0 /build/pages.lua /pages.lua
COPY --from=0 /build/luahttp /luahttp
COPY --from=0 /build/static /static
RUN cp /usr/share/zoneinfo/Europe/Moscow /etc/localtime
CMD ["/bin/sh", "-c", "/main -c /ynote.lua"]
