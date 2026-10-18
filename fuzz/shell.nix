# Supply local checkouts to avoid resolving flake registry entries over GitHub.
{ nixpkgsPath, rustOverlayPath }:
let
  pkgs = import nixpkgsPath {
    overlays = [ (import rustOverlayPath) ];
  };
in
pkgs.mkShell {
  packages = [
    (pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.minimal))
    pkgs.cargo-fuzz
  ];
}
