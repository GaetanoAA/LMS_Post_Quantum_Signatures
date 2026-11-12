"""Grafici dei benchmark (matplotlib, PNG ad alta risoluzione per le slide)."""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker

SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]
TEXT, TEXT2, GRID, SURFACE, NEUTRAL = "#0b0b0b", "#52514e", "#e6e5e0", "#ffffff", "#a3a29c"
WS = (1, 2, 4, 8)

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 13,
    "axes.edgecolor": GRID, "axes.labelcolor": TEXT2, "axes.titlecolor": TEXT,
    "xtick.color": TEXT2, "ytick.color": TEXT2, "axes.grid": True,
    "grid.color": GRID, "grid.linewidth": 0.8, "axes.axisbelow": True,
    "axes.spines.top": False, "axes.spines.right": False,
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE,
    "legend.frameon": False, "legend.labelcolor": TEXT2,
})


def _save(fig, out, name):
    fig.tight_layout()
    fig.savefig(os.path.join(out, name), dpi=200)
    plt.close(fig)


def make_charts(data, out):
    os.makedirs(out, exist_ok=True)
    sizes, tm = data["sizes"], data["timings"]

    # 1) Dimensione della firma al variare di w, una linea per altezza h
    fig, ax = plt.subplots(figsize=(8, 4.8))
    x = list(range(len(WS)))
    for k, h in enumerate((5, 10, 15, 20, 25)):
        ys = [sizes[f"w{w}_h{h}"] / 1024 for w in WS]
        ax.plot(x, ys, color=SERIES[k], lw=2, marker="o", ms=8,
                markeredgecolor=SURFACE, markeredgewidth=2, label=f"h = {h}")
    ax.set_xticks(x, [f"w = {w}" for w in WS])
    ax.set_ylabel("Dimensione firma (KB)")
    ax.set_ylim(-0.6, 10)
    ax.set_xlim(-0.3, 3.3)
    ax.legend(loc="upper right")
    for w_i, w in enumerate(WS):
        v = sizes[f"w{w}_h10"]
        ax.annotate(f"{v} B", (w_i, v / 1024), textcoords="offset points",
                    xytext=(0, -26), ha="center", color=TEXT, fontsize=11,
                    bbox=dict(boxstyle="round,pad=0.2", fc=SURFACE, ec="none"))
    ax.set_title("Etichette: dimensione esatta con h = 10", fontsize=11,
                 color=TEXT2, loc="left")
    _save(fig, out, "dimensione_firma.png")

    # 2) Tempi di firma e verifica (h = 10): barre affiancate
    fig, ax = plt.subplots(figsize=(8, 4.8))
    bw = 0.36
    for k, (key, lab) in enumerate((("sign_ms", "Firma"), ("verify_ms", "Verifica"))):
        vals = [tm[f"w{w}_h10"][key] for w in WS]
        pos = [i + (k - 0.5) * (bw + 0.02) for i in x]
        bars = ax.bar(pos, vals, width=bw, color=SERIES[k], label=lab, edgecolor=SURFACE, linewidth=2)
        for b, v in zip(bars, vals):
            ax.annotate(f"{v:.1f}", (b.get_x() + b.get_width() / 2, v),
                        textcoords="offset points", xytext=(0, 4), ha="center",
                        color=TEXT, fontsize=11)
    ax.set_xticks(x, [f"w = {w}" for w in WS])
    ax.set_ylabel("Tempo mediano (ms)")
    ax.legend(loc="upper left")
    _save(fig, out, "tempi_firma_verifica.png")

    # 3) Tempo di generazione chiavi (h = 10)
    fig, ax = plt.subplots(figsize=(8, 4.8))
    vals = [tm[f"w{w}_h10"]["keygen_s"] for w in WS]
    bars = ax.bar(x, vals, width=0.55, color=SERIES[0])
    for b, v in zip(bars, vals):
        ax.annotate(f"{v:.1f} s", (b.get_x() + b.get_width() / 2, v),
                    textcoords="offset points", xytext=(0, 4), ha="center",
                    color=TEXT, fontsize=11)
    ax.set_xticks(x, [f"w = {w}" for w in WS])
    ax.set_ylabel("Generazione chiavi (s), 1024 foglie")
    _save(fig, out, "tempo_keygen.png")

    # 4) Confronto dimensioni firma con altri schemi
    rows = [
        ("LMS H10 / W8", sizes["w8_h10"], True),
        ("LMS H10 / W4", sizes["w4_h10"], True),
        ("LMS H20 / W4", sizes["w4_h20"], True),
    ] + [(n, d["sig"], False) for n, d in data["others"].items()]
    rows.sort(key=lambda r: r[1])
    fig, ax = plt.subplots(figsize=(8, 4.8))
    names = [r[0] for r in rows]
    vals = [r[1] for r in rows]
    cols = [SERIES[0] if r[2] else NEUTRAL for r in rows]
    bars = ax.barh(names, vals, color=cols, height=0.6)
    for b, v in zip(bars, vals):
        ax.annotate(f"{v:,} B".replace(",", "."), (v, b.get_y() + b.get_height() / 2),
                    textcoords="offset points", xytext=(6, 0), va="center",
                    color=TEXT, fontsize=11)
    ax.set_xlabel("Dimensione firma (byte)")
    ax.set_xlim(0, max(vals) * 1.18)
    ax.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(
        lambda v, _: f"{int(v):,}".replace(",", ".")))
    ax.grid(axis="y", visible=False)
    ax.tick_params(axis="y", colors=TEXT)
    _save(fig, out, "confronto_schemi.png")
