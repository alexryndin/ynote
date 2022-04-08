CFLAGS=-g -O2 -Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes -pedantic -DNDEBUG -isystemcontrib/chelpers/src -isystemcontrib/bstring/bstring -isystemcontrib/json-parser -isystemcontrib/json-builder -isystemcontrib/md4c/src -Ilib $(OPTFLAGS)
LDLIBS=-ldl -levent -pedantic -lsqlite3 -lm $(OPTLIBS)
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

dev: CFLAGS := $(filter-out -O2,$(CFLAGS))
dev: CFLAGS := $(filter-out -DNDEBUG,$(CFLAGS))
dev: CFLAGS := $(filter-out -pedantic,$(CFLAGS))
dev: all

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
