{ pkgs ? import ./pkgs.nix {} }:

with pkgs;

let
  inherit (rust.packages.nightly) rustPlatform;
  inherit (darwin.apple_sdk.frameworks) CoreServices Security;
in

{
  hp-admin-authorize = buildRustPackage rustPlatform {
    name = "hp-admin-authorize";
    src = gitignoreSource ./server;
    cargoDir = ".";

    buildInputs = lib.optionals stdenv.isDarwin [ Security ];

    doCheck = false;
  };

}
