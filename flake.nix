{
  description = "The flake.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
      in {
        devShells.default = with pkgs;
          mkShell {
            buildInputs = [ 
							(rust-bin.selectLatestNightlyWith (toolchain: toolchain.default.override {
								extensions = [ "rust-src" "llvm-tools" ];
								targets = [ "x86_64-unknown-none" ];
							}))
						];
            shellHook = ''
              export ROOTD=$(pwd)
              export SHELL=${pkgs.lib.getExe pkgs.bashInteractive}
              echo "Why not?"
						'';
					};
				});
}
