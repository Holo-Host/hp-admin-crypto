{ pkgs ? import ./nixpkgs.nix {} }:

with pkgs;

mkShell {
  inputsFrom = lib.attrValues (import ./. { inherit pkgs; });

  HPOS_CONFIG_PATH = "${./server/resources/test/hpos-config-v2.json}";
}
