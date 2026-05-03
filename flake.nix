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

        # go-size-analyzer is not in nixpkgs (yet). We grab the
        # upstream-built binary rather than `buildGoModule` because the
        # repo embeds a pnpm-built web UI via go:embed — building from
        # source would require also setting up the JS toolchain.
        # Acceptable trade-off for a dev/diagnostic tool.
        #
        # Bump procedure (manual — Renovate can't refresh the four
        # per-arch hashes on a `fetchurl` bump):
        #   1. update `version` below
        #   2. curl -sL https://github.com/Zxilly/go-size-analyzer/releases/download/v<v>/checksums.txt
        #   3. for each (arch, hex) pair: hash = "sha256-$(echo <hex> | xxd -r -p | base64)"
        goSizeAnalyzer = let
          version = "1.12.6";
          assets = {
            "x86_64-linux"   = { suffix = "linux_amd64";  hash = "sha256-k8NBdryks8GIFpADqs0Er0uLXK9BOfg8th01GnVaILA="; };
            "aarch64-linux"  = { suffix = "linux_arm64";  hash = "sha256-hX7LtqLJIX1PTb+8tm4CVE/IuFTGUVDFWipGUMWVPWg="; };
            "x86_64-darwin"  = { suffix = "darwin_amd64"; hash = "sha256-v2IOQEsMShTgW9bntHGsp7MeNI8iV7nSNT5q7KrXj3o="; };
            "aarch64-darwin" = { suffix = "darwin_arm64"; hash = "sha256-5lyZJPD6i1h08wjlg/hBV8wr8MjpFuykCn5bEfyZ1LU="; };
          };
          asset = assets.${system} or (throw "go-size-analyzer: unsupported system ${system}");
        in pkgs.stdenvNoCC.mkDerivation {
          pname = "go-size-analyzer";
          inherit version;
          src = pkgs.fetchurl {
            url = "https://github.com/Zxilly/go-size-analyzer/releases/download/v${version}/go-size-analyzer_${version}_${asset.suffix}.tar.gz";
            hash = asset.hash;
          };
          sourceRoot = ".";
          # Upstream ships the binary as `gsa` — install it under that
          # name (matches the project's own README usage).
          installPhase = ''
            install -Dm755 gsa $out/bin/gsa
          '';
        };
      in {
        devShells.default = pkgs.mkShell {
          # Go is intentionally unpinned: the dev shell ships whatever Go
          # version nixpkgs currently exposes, and Go's GOTOOLCHAIN=auto
          # mechanism transparently downloads the exact toolchain declared
          # in go.mod. Single source of truth: the `go` directive in go.mod.
          packages = [
            dagger.packages.${system}.dagger
            goSizeAnalyzer
          ] ++ (with pkgs; [
            go
            go-task
            goreleaser
            tilt
            k3d
            kubectl
            kubernetes-helm
            cosign
            rekor-cli
            goda
          ]);
        };
      });
}
