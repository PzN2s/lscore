# lscore

![lscore](assets/lscore-banner.gif)

linux health score in one command

lscore is a read-only offline health check for linux

it runs 27 checks in parallel and prints a 0-100 score with a letter grade and five category scores

speed security privacy storage battery & heat

plus a prioritized list of issues with concrete fixes

one python file with stdlib only and py3.8+

read-only offline honest zero deps no telemetry

## install

```sh
./install.sh
lscore
```

```sh
./install.sh --user
./install.sh --system
./install.sh --prefix dir
./uninstall.sh
```

also via `pipx install .`
`nix profile install .`
or the included aur `pkgbuild`

## supported distros

```text
debian ubuntu          apt
fedora rhel            dnf
arch                   pacman
opensuse               zypper
alpine                 apk
void                   xbps
fedora silverblue      rpm-ostree
fedora kinoite         rpm-ostree
gentoo                 emerge partial
nixos                  native
```

any other linux with py3.8+ works
checks that do not apply are skipped
