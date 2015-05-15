#

# random.c is used for test files
LIB_SRCS = ayden32.c ayden64.c ayden_init.c prng.c sha256.c random.c
LIB_OBJS = $(LIB_SRCS:%.c=build/%.o)
LIB_TARGET = build/libintncoder.a

CFLAGS = -m32 -g -Iinclude

.PHONY: all clean distclean test

default: all

all: test

init: 
	@[ -d build ] || mkdir build

build/%.o: src/%.c
	gcc $(CFLAGS) -o $@ -c $<

build/%.o: test/%.c
	gcc $(CFLAGS) -o $@ -c $<

$(LIB_TARGET): init $(LIB_OBJS)
	ar r $@ $(LIB_OBJS)

build/test_ayden32: build/test_ayden32.o $(LIB_TARGET)
	g++ -static -o $@ build/test_ayden32.o $(LIB_TARGET)

build/test_ayden64: build/test_ayden64.o $(LIB_TARGET)
	g++ -static -o $@ build/test_ayden64.o $(LIB_TARGET)

test: init build/test_ayden32 build/test_ayden64
	./build/test_ayden32 || exit 1
	./build/test_ayden64 || exit 1
	./build/test_ayden32 my-secret-key 1000 20000 40000 || exit 1

clean: 
	@rm -rf build/*

distclean: clean
	@rm -rf windows/Debug/ windows/Release/ windows/ipch/ windows/x64/ windows/*.sdf windows/*.suo

