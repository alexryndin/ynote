CFLAGS=-O2 -Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes -Wimplicit-function-declaration -pedantic -DNDEBUG \
			 -isystemcontrib/chelpers/src                                                  \
			 -isystemcontrib/bstring/bstring                                               \
			 -isystemcontrib/bstring/bstring/bstrlib.h                                     \
			 -isystemcontrib/json-parser                                                   \
			 -isystemcontrib/json-builder                                                  \
			 -isystemcontrib/md4c/src                                                      \
			 -Icontrib/bstring/bstring                                               \
			 -Ilib                                                                         \
			 $(OPTFLAGS)                                                                   \
			 $(shell pkg-config lua$(LUA_VER) --cflags)

LDLIBS=-ldl -levent -pedantic -lsqlite3 -lm -lcurl -lmicrohttpd \
			 $(shell pkg-config lua$(LUA_VER) --libs)              \
       $(OPTLIBS)

PREFIX?=/usr/local

BIN_SRC=$(wildcard *.c)
BIN=$(patsubst %.c,%,$(BIN_SRC))

TEST_SRC=$(wildcard tests/*_tests.c)
TESTS=$(patsubst %.c,%,$(TEST_SRC))

LIB_SRC=$(wildcard lib/*.c)
LIB=$(patsubst %.c,%.o,$(LIB_SRC))

EXTERNAL_SRC=$(wildcard contrib/**/bstring/bstrlib.c contrib/**/src/*.c contrib/json-*/*.c contrib/md4c/src/*c)
EXTERNAL_SRC_NO_TESTS=$(filter-out %test.c, $(EXTERNAL_SRC))
EXTERNAL=$(patsubst %.c,%.o,$(EXTERNAL_SRC_NO_TESTS))

all: $(BIN) $(SHARED) tests

bindgen:
	BINDGEN_EXTRA_CLANG_ARGS="-Icontrib/chelpers/src -Icontrib/bstring/bstring -Icontrib/json-parser" bindgen lib/dbw.h

dev: CFLAGS := $(filter-out -O2,$(CFLAGS))
dev: CFLAGS := $(filter-out -DNDEBUG,$(CFLAGS))
dev: CFLAGS := $(filter-out -pedantic,$(CFLAGS))
dev: CFLAGS += -g
dev: all

OUT_DIR ?= .
TARGET_LIB=$(OUT_DIR)/libdbw.a

$(TARGET_LIB): $(LIB) $(EXTERNAL) build.rs
	ar rcs $(TARGET_LIB) $(LIB) $(EXTERNAL)
	ranlib $(TARGET_LIB)

lib: $(TARGET_LIB)

$(BIN): $(LIB) $(EXTERNAL)

$(TESTS): $(LIB) $(EXTERNAL)

# The Unit Tests
.PHONY: tests
tests: CFLAGS += $(TARGET)
tests: CFLAGS := $(filter-out -pedantic,$(CFLAGS))
tests: CFLAGS := $(filter-out -DNDEBUG,$(CFLAGS))
tests: $(TESTS)
	sh ./tests/runtests.sh


build:
	@mkdir -p build

# The Cleaner
clean:
	@echo $(EXTERNAL_SRC_NO_TESTS)
	rm -rf build $(OBJECTS) $(TESTS) $(BIN) $(LIB) $(EXTERNAL)
	rm -f tests/tests.log
	find . -name "*.gc*" -delete
