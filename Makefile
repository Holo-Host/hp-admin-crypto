# 
# Test and build project
# 
# This Makefile is primarily instructional; you can simply enter the Nix environment for
# holochain-rust development (supplied by holo=nixpkgs; see pkgs.nix) via `nix-shell` and
# perform Rust and Javascript project build and test procedures manually, if you prefer.
#

SHELL		= bash


# External targets; Uses a nix-shell environment to obtain Holochain runtimes, run tests, etc.
.PHONY: all
all: 		nix-test


# nix-test, nix-install, ...
# 
# Provides a nix-shell environment, and runs the desired Makefile target.  It is recommended that
# you add `substituters = ...` and `trusted-public-keys = ...` to your nix.conf (see README.md), to
# take advantage of cached Nix and Holo build assets.
nix-%:
	nix-shell --pure --run "make $*"


# Build all targets
.PHONY: build
build:		client/pkg/hp-admin-keypair_node.js	\
		target/release/hp-admin-crypto-server

client/pkg/hp-admin-keypair_node.js: client/src/lib.rs
	cd client && ./build.sh

target/release/hp_admin_crypto_server: server/src/main.rs
	cargo build --release


# Test all targets, building as necessary
.PHONY: test test-rust test-js
test:		test-rust test-js

test-rust:
	cargo test

# A (poor) example of starting a server, running some tests, and shutting down the server
test-js:	target/release/hp-admin-crypto-server
	@PID=$$( $< > $@.out 2>&1 & echo $$! ); \
	EXP="401 Unauthorized"; \
	GOT=$$( curl -v -X POST \
	  --header "x-hpos-admin-signature: boo==" \
	  --data '{"method": "get", "request": "/api/v1/config?a=b", "body": "something" }' \
	    http://127.0.0.1:2884 2>&1 \
	  | sed -ne "s/^< HTTP\/1.1 \([^\r\n]*\).*$$/\1/p" ); \
	[[ "$$GOT" == "$$EXP" ]] && printf "OK: Expected: '%s'" "$$EXP" || printf "*** ERROR: Expected: '%s', Got: '%s'" "$$EXP" "$$GOT"; \
	kill $$PID
