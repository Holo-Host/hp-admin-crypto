{ pkgs ? import ./nixpkgs.nix {} }:

with pkgs;

mkShell {
  inputsFrom = lib.attrValues (import ./. { inherit pkgs; });

  HPOS_CONPIG_PATH = "${./server/resources/test/hpos-config.json}";
}
