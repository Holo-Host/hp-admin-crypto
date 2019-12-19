{ pkgs ? import ./pkgs.nix {} }:

with pkgs;

let
  inherit (rust.packages.nightly) rustPlatform;
  inherit (darwin.apple_sdk.frameworks) Security;
in

{
  hp-admin-crypto-server = buildRustPackage rustPlatform {
    name = "hp-admin-crypto-server";
    src = gitignoreSource ./server;
    cargoDir = ".";

    buildInputs = lib.optionals stdenv.isDarwin [ Security ];
  };

  hp-admin-keypair = buildRustPackage rustPlatform {
	  name = "hp-admin-keypair";
    src = gitignoreSource ./client;
    cargoDir = ".";

    nativeBuildInputs = with buildPackages; [
      nodejs-12_x
      pkgconfig
      (wasm-pack.override { inherit rustPlatform; })
    ];

    # buildInputs = [ openssl ];
  };
}
