{
  description = "tsidp-flags devshell: node, pnpm, dhall, python, just";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.nodejs_22
            pkgs.pnpm
            pkgs.dhall
            pkgs.dhall-json
            pkgs.python3
            pkgs.just
            pkgs.gitleaks
          ];
          shellHook = ''
            export XDG_CACHE_HOME="''${XDG_CACHE_HOME:-$PWD/.dhall-cache}"
          '';
        };
      });
    };
}
