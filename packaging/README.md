# Packaging

The tool is one Python file with no dependencies, so every package is a thin
wrapper around `lscore.py`.

## pipx / pip

```console
$ pipx install .
$ lscore --version
```

`pyproject.toml` reads the version directly from `lscore.__version__`, so both
report the same version.

## Nix

```console
$ nix run .#          # run without installing
$ nix build .#        # ./result/bin/lscore
$ nix profile install .
```

The flake uses Nixpkgs' `python3` and installs the manual page as well, so
`man lscore` works after `nix profile install .`; `nix build .#` places it at
`./result/share/man/man1/lscore.1.gz`.

## Arch (AUR)

`aur/PKGBUILD` builds from local files by default:

```console
$ cp lscore.py LICENSE packaging/aur/
$ cp man/lscore.1 packaging/aur/
$ cd packaging/aur
$ makepkg -si
```

The package installs `lscore.py` to `/usr/bin/lscore`, the license, and the man
page to `/usr/share/man/man1/lscore.1`.

For a real AUR upload, replace the `source` list with the release tarball
and run `updpkgsums` so `sha256sums` contains real checksums (AUR rejects
`SKIP`). Add a `url=` for your project page, and keep `pkgver` in step with
`lscore.__version__`.
