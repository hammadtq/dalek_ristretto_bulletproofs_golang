ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

all: library build

clean:
	rm -rf ./lib/dalek_rangeproofs/target
	rm -f ./lib/dalek_rangeproofs/Cargo.lock ./lib/librange_proofs.dylib dalek_rangeproofs

library:
	$(MAKE) -C lib/dalek_rangeproofs build

build:
	cp lib/dalek_rangeproofs/target/release/libdalek_rangeproofs.dylib ./lib
	go build -ldflags="-r $(ROOT_DIR)lib" -o dalek_rangeproofs


run: build
	./dalek_rangeproofs


