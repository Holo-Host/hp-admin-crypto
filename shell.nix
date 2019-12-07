{ pkgs ? import ./pkgs.nix {} }:

with pkgs;

mkShell {
  inputsFrom = lib.attrValues (import ./. { inherit pkgs; });

  HPOS_STATE_PATH = "${./server/resources/test/hpos-state.json}";
}
