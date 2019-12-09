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
}
