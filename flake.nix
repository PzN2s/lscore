{
  description = "lscore - a one-command health check for your Linux machine";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          lscore = pkgs.stdenvNoCC.mkDerivation {
            pname = "lscore";
            version = "0.8.0";
            # Keep build artifacts out of the source hash.
            src = builtins.path {
              path = ./.;
              name = "lscore-source";
              filter = path: _type:
                let base = baseNameOf (toString path); in
                !(builtins.elem base [ ".git" "__pycache__" "dist" "build"
                                       "result" "lscore-card.svg" ])
                && builtins.match ".*\\.(pyc|egg-info)" base == null;
            };

            nativeBuildInputs = [ pkgs.makeWrapper ];

            installPhase = ''
              runHook preInstall
              install -Dm755 lscore.py $out/share/lscore/lscore.py
              install -Dm644 man/lscore.1 $out/share/man/man1/lscore.1
              makeWrapper ${pkgs.python3.interpreter} $out/bin/lscore \
                --add-flags "$out/share/lscore/lscore.py"
              runHook postInstall
            '';

            meta = with pkgs.lib; {
              description = "A one-command health check for your Linux machine";
              license = licenses.mit;
              platforms = platforms.linux;
              mainProgram = "lscore";
            };
          };
        in
        {
          default = lscore;
          lscore = lscore;
        });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/lscore";
        };
      });

      devShells = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
          default = pkgs.mkShell {
            packages = [ pkgs.python3 pkgs.shellcheck ];
          };
        });
    };
}
