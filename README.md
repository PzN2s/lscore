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

## commands

the one you will use most

```sh
lscore
```

everyday commands

```sh
lscore                  score your machine
lscore -v               show every check
lscore -q               print only the number
lscore --history        show your score over time
lscore --no-history     do not record this run
```

fix and share

```sh
lscore --fix            print fixes to review (runs nothing)
lscore --card           save an svg score card
lscore --share          plain text for a post
lscore --badge          markdown badge for your readme
```

choose checks

```sh
lscore --only storage       run one category
lscore --only disk,journal  run exact checks
lscore --skip privacy       skip a category
lscore --list-checks        list all 27 checks
```

scripts and ci

```sh
lscore --json               machine-readable report
lscore --min 80             exit 1 below 80
lscore --fail-on warn       exit 1 on a warning or failure
lscore --compare old.json   compare with an old report
```

display

```sh
lscore --ascii          plain ascii symbols
lscore --no-color       no colors
lscore --theme basic    light terminal palette
lscore --completion bash  shell completion
lscore --help           full help
```

`--fix` only prints commands. `--card` writes one svg file. the only other file lscore writes is its own score history (opt out with `--no-history`).

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
