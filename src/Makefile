
uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

WARN=-Wall -W -Wno-missing-field-initializers
# Compile flags for linux / osx
ifeq ($(uname_S),Linux)
	SHOBJ_CFLAGS ?= -W -Wall -fno-common -g -ggdb -std=c11 -O2 $(WARN) $(OPTIMIZATION)
	SHOBJ_LDFLAGS ?= -shared -lpq
else
	SHOBJ_CFLAGS ?= -W -Wall -dynamic -fno-common -g -ggdb -std=c11 -O2 $(WARN) $(OPTIMIZATION)
	SHOBJ_LDFLAGS ?= -bundle -undefined dynamic_lookup -lpq
endif

.SUFFIXES: .c .so .xo .o


.c.xo:
	$(CC) -I. $(CFLAGS) $(SHOBJ_CFLAGS) -fPIC -c $< -o $@

all: redis-acl.so


redis-acl.xo: ./redismodule.h

redis-acl.so: redis-acl.xo
	$(LD) -o $@ $^ $(SHOBJ_LDFLAGS) $(LIBS) -lc

clean:
	rm -rf *.xo *.so *.o
