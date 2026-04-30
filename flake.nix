{
  description = "x509-certificate-exporter dev shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    # Dagger is not in nixpkgs; the upstream maintains its own flake.
    # https://github.com/dagger/nix
    dagger.url = "github:dagger/nix";
    dagger.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, dagger }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        devShells.default = pkgs.mkShell {
          # Go is intentionally unpinned: the dev shell ships whatever Go
          # version nixpkgs currently exposes, and Go's GOTOOLCHAIN=auto
          # mechanism transparently downloads the exact toolchain declared
          # in go.mod. Single source of truth: the `go` directive in go.mod.
          packages = [
            dagger.packages.${system}.dagger
          ] ++ (with pkgs; [
            go
            go-task
            goreleaser
            tilt
            k3d
            kubectl
            kubernetes-helm
            cosign
            slsa-verifier
            rekor-cli
            ratchet
          ]);
        };
      });
}
