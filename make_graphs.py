import collections
import json

from pathlib import Path
from typing import List

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

_RENAME = {
    "method": "Method",
    "merkle": "Merkle BPT",
    "plain": "Basic dictionary",
    "ed25519-sign": "Sign",
    "ed25519-verify": "Verify",
    "pedersen-commit": "Commit",
    "pedersen-commit-verify": "Verify",
    "pedersen-prove-equality": "Prove equality",
    "pedersen-prove-equality-verify": "Verify equality",
    "policy-sign": "Sign",
    "policy-verify": "Verify",
}

# Each column in the document is 3.25 inchecs
COL_WIDTH = 3.25
# 2 * COL_WIDTH + margin
FULL_WIDTH = 7


def plot_sizes(size_data):
    fig, axes = plt.subplots(3, 1, figsize=(COL_WIDTH, 2), sharex=True)

    sns.lineplot(
        ax=axes[0],
        data=size_data,
        x="num_packages",
        y="initial_fetch_bytes",
        hue="method",
        style="method",
        markers=True,
    )
    axes[0].set(
        ylabel="Bandwidth (B)",
        xscale="log",
        yscale="log",
    )
    axes[0].set_title("Initial fetch", pad=0.2)
    legend = axes[0].get_legend()
    legend.set_title("")
    for t in legend.texts:
        t.set_text(_RENAME[t.get_text()])

    sns.lineplot(
        ax=axes[1],
        data=size_data,
        x="num_packages",
        y="proof_size_bytes",
        hue="method",
        style="method",
        markers=True,
        legend=None,
    )
    axes[1].set(ylabel="Size (B)", yscale="log")
    axes[1].set_title("Lookup proof", pad=0.2)

    sns.lineplot(
        ax=axes[2],
        data=size_data,
        x="num_packages",
        y="map_size_bytes",
        hue="method",
        style="method",
        markers=True,
        legend=None,
    )
    axes[2].set(
        ylabel="Size (B)",
        yscale="log",
        xlabel="Repository package count",
    )
    axes[2].set_title("Server storage", pad=0.2)


def read_data(paths: List[Path]):
    raw_data = []
    for path in paths:
        with Path(path).open() as f:
            raw_data.extend(list(map(json.loads, f)))
    raw_data = [x for x in raw_data if x["reason"] == "benchmark-complete"]
    by_ids = collections.defaultdict(list)
    for x in raw_data:
        parts = x["id"].split("/")
        if len(parts) == 1:
            by_ids[parts[0]] = x
        else:
            by_ids["/".join(parts[:-1])].append(x)
    return by_ids


NS_PER = {
    "ns": 1,
    "μs": 1000,
    "ms": 1000 * 1000,
    "s": 1000 * 1000 * 1000,
}


def entry_to_times(entry, unit):
    assert entry["unit"] == "ns"
    return [
        x / y / NS_PER[unit]
        for x, y in zip(entry["measured_values"], entry["iteration_count"])
    ]


def plot_signatures(data):
    plt.figure(figsize=(FULL_WIDTH, 0.75))
    cols = ["ed25519-sign", "ed25519-verify"]
    col_data = {_RENAME.get(x, x): entry_to_times(data[x], "μs") for x in cols}
    df = pd.DataFrame.from_dict(col_data)
    fig = sns.violinplot(
        data=df,
        orient="h",
    )
    fig.set(xlabel="Time (μs)")


def plot_commitments(data):
    plt.figure(figsize=(FULL_WIDTH, 1.25))
    plt.tight_layout()
    cols = [
        "pedersen-commit",
        "pedersen-commit-verify",
        "pedersen-prove-equality",
        "pedersen-prove-equality-verify",
    ]
    col_data = {_RENAME.get(x, x): entry_to_times(data[x], "μs") for x in cols}
    df = pd.DataFrame.from_dict(col_data)
    fig = sns.violinplot(
        data=df,
        orient="h",
    )
    fig.set(
        xlabel="Time (μs)",
    )


def plot_policy(data):
    cols = [
        "policy-sign",
        "policy-verify",
    ]
    col_data = {_RENAME.get(x, x): entry_to_times(data[x], "μs") for x in cols}
    df = pd.DataFrame.from_dict(col_data)
    fig = sns.violinplot(
        data=df,
        orient="h",
    )
    fig.set(xlabel="Time (μs)")


def plot_maps(data):
    action_units = {"make-tree": "s", "lookup": "ns", "verify": "μs", "insert": "μs"}
    df = None
    for (action, units) in action_units.items():
        method_dfs = []
        for method in ["merkle", "plain"]:
            method_dfs.append(
                pd.concat(
                    [
                        pd.DataFrame.from_dict(
                            {
                                "num_packages": int(x["id"].split("/")[-1]),
                                action: entry_to_times(x, units),
                                "method": method,
                            }
                        )
                        for x in data[f"{method}/{action}"]
                    ]
                )
            )
        new_df = pd.concat(method_dfs).set_index(["num_packages", "method"])
        if df is not None:
            df = pd.concat([df, new_df], axis="columns")
        else:
            df = new_df
    # we batched the insert benchmarks because we had too-high measurement overhead otherwise
    df["insert"] /= 10_000

    fig, axes = plt.subplots(4, 1, figsize=(COL_WIDTH, 2.5), sharex=True)

    ax = axes[0]
    sns.lineplot(
        ax=ax,
        data=df,
        x="num_packages",
        y="make-tree",
        hue="method",
        style="method",
        markers=True,
    )
    ax.set_title("Server: Initialization", pad=1)
    ax.set(ylabel=f"Time ({action_units['make-tree']})")  # , yscale="log")
    ax.set(xscale="log")  # , yscale="log")
    sns.move_legend(ax, "upper left")
    legend = ax.get_legend()
    legend.set_title("")
    for t in legend.texts:
        t.set_text(_RENAME[t.get_text()])

    ax = axes[3]
    sns.lineplot(
        ax=ax,
        data=df,
        x="num_packages",
        y="verify",
        hue="method",
        style="method",
        markers=True,
        legend=None,
    )
    ax.set(ylabel=f"Time ({action_units['verify']})")  # , yscale="log")
    ax.set_title("User: Lookup/Verify", pad=1)

    ax = axes[1]
    sns.lineplot(
        ax=ax,
        data=df,
        x="num_packages",
        y="insert",
        hue="method",
        style="method",
        markers=True,
        legend=None,
    )
    ax.set_title("Server: Insert package", pad=1)
    ax.set(
        ylabel=f"Time ({action_units['insert']})",
    )

    ax = axes[2]
    sns.lineplot(
        ax=ax,
        data=df.reset_index()[df.reset_index()["method"] != "plain"],
        x="num_packages",
        y="lookup",
        hue="method",
        style="method",
        markers=True,
        legend=None,
    )
    ax.set(
        ylabel=f"Time ({action_units['lookup']})",
    )
    ax.set_title("Server: Prove", pad=1)
    ax.set_ylim(0, 650)

    axes[-1].set(xlabel="Repository package count")


def plot_end_to_end(data):
    action_units = {"sign": "μs", "verify": "μs"}
    df = None
    for (action, units) in action_units.items():
        new_df = pd.concat(
            [
                pd.DataFrame.from_dict(
                    {
                        "num_packages": int(x["id"].split("/")[-1]),
                        action: entry_to_times(x, units),
                    }
                )
                for x in data[f"end-to-end/{action}"]
            ]
        ).set_index(["num_packages"])
        if df is not None:
            df = pd.concat([df, new_df], axis="columns")
        else:
            df = new_df

    fig, axes = plt.subplots(2, 1, figsize=(COL_WIDTH, 1), sharex=True)
    plt.tight_layout()

    sns.lineplot(
        ax=axes[0],
        data=df,
        x="num_packages",
        y="sign",
        markers="o",
    )
    axes[0].set_ylim(bottom=0, top=500)
    axes[0].set_ylabel(f"Time ({action_units['sign']})", rotation="vertical")
    axes[0].set_title("Sign", pad=0)

    sns.lineplot(
        ax=axes[1],
        data=df,
        x="num_packages",
        y="verify",
        markers=True,
        legend=None,
    )
    axes[1].set(ylabel=f"Time ({action_units['verify']})")
    axes[1].set(xscale="log", xlabel="Items in map")
    axes[1].set_ylim(bottom=0, top=500)
    axes[1].set_title("Verify", pad=0)


def main():
    data_flat = read_data([Path("data.json")])
    data_maps = read_data([Path("data.json")])
    data_e2e = read_data([Path("data.json")])
    size_data = pd.read_csv(Path("sizes.csv"))

    fig_dir = Path("figures")
    fig_dir.mkdir(exist_ok=True)

    sns.set(font_scale=0.4)
    show = False
    for name, plot in [
        ("commitments", lambda: plot_commitments(data_flat)),
        ("signature", lambda: plot_signatures(data_flat)),
        ("policy", lambda: plot_policy(data_flat)),
        ("maps", lambda: plot_maps(data_maps)),
        ("e2e", lambda: plot_end_to_end(data_e2e)),
        ("sizes", lambda: plot_sizes(size_data)),
    ]:
        plt.tight_layout()
        plot()
        if show:
            plt.show()
        plt.savefig(fig_dir / f"{name}.png", bbox_inches="tight", dpi=300)
        plt.figure().clear()


if __name__ == "__main__":
    main()
