
.PHONY: all ;

all: ../Dockerfile ../Dockerfile.release ;

../Dockerfile:         Dockerfile.header.in Dockerfile.src.in     Dockerfile.runtime.in
	cat $^ >$@

../Dockerfile.release: Dockerfile.header.in Dockerfile.release.in Dockerfile.runtime.in
	cat $^ >$@

