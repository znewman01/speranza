# Speranza

Experiments for Speranza, a system for private-but-usable package signing.

## Overview

The repository contains:

- a Rust library implementing:
  - Pedersen commitments (`src/commitments/pedersen.rs`)
  - a Merkle binary prefix tree (`src/maps/merkle_bpt.rs`)
  - a signing system
- Code for reproducing the results and graphs from the paper:
  - `benches/` contains a benchmark
  - `make_graphs.py` generates graphs.

## Requirements

Requirements:

- Rust toolchain (we used the version described in `rust-toolchain.toml`)
  including the package manager/build tool `cargo`.
- cargo-criterion (run `cargo install cargo-criterion`).
- Python 3 with seaborn (and its dependencies) installed for generating figures.

The easiest way to reproduce will be to use [Nix]: the project is described in a
`flake.nix` file. Running `nix develop` on a recent version of Nix will install
build and development dependencies.

[Nix]: https://nixos.org/
[cargo-criterion]: https://github.com/bheisler/cargo-criterion


## Reproducing results and figures

First, make sure the project builds and tests pass:

```shell
$ cargo test
```

This will download and install all dependencies.

Now, collect the data:

```shell
$ cargo run --bin sizes > sizes.csv
$ cargo criterion --message-format=json > data.json
```

This shouldn't take more than an hour or so. If the above doesn't work, our data
is checked into the repo.

Now, generate the plots:

```shell
$ python make_graphs.py
```

The figures will be in the `figures/` directory.
