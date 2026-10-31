#!/usr/bin/env python3
"""3.2 Відбір ознак (журнал, п. 9.2). Усі розрахунки — лише на ночі 1 (набір розробки); ніч 2 не використовується.
Етапи:
  0) демонстрація артефакту невдалих з'єднань obfs4 (чому потоки meta_no_payload=1 вилучено);
  А) вилучення за правилами: сталі ознаки та ознаки, що описують стенд, а не трафік;
  Б) кореляційний фільтр: кластери ознак з |ρ Спірмена| ≥ 0.95, з кластера лишається ознака з найбільшою взаємною інформацією;
  В) ранжування: перестановкова важливість (permutation importance) Random Forest на валідаційних фолдах групової CV;
  Г) крива macro-F1 від кількості k найважливіших ознак; обрано найменше k за правилом «одної стандартної похибки»;
  Д) абляція груп ознак (що втрачає модель без розмірів, інтервалів тощо).
Результат: results/3_2/selected_features.json, таблиці *.csv, рисунки *.png, звіт report.txt.
Запуск: python3 scripts/select_features.py"""
import json

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy.cluster.hierarchy import fcluster, leaves_list, linkage
from scipy.spatial.distance import squareform
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import mutual_info_classif
from sklearn.inspection import permutation_importance
from sklearn.metrics import f1_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.utils.class_weight import compute_sample_weight

from common import RES, SEED, load

OUT = RES / "3_2"
CORR = 0.95
BLUE = "#2a78d6"
log = []


def say(*a):
    s = " ".join(str(x) for x in a)
    print(s, flush=True)
    log.append(s)


def rf(n=200):
    return RandomForestClassifier(n_estimators=n, n_jobs=-1, random_state=SEED)


def cv_f1(df, feats, n=200, folds=5, per_class=False):
    """macro-F1 Random Forest у груповій стратифікованій CV: потоки однієї сесії — завжди в одному фолді."""
    cv = StratifiedGroupKFold(n_splits=folds, shuffle=True, random_state=SEED)
    X, y, g = df[feats].to_numpy(), df.label.to_numpy(), df.meta_session.to_numpy()
    res, pcs = [], []
    for tr, va in cv.split(X, y, g):
        m = rf(n).fit(X[tr], y[tr], sample_weight=compute_sample_weight("balanced", y[tr]))
        p = m.predict(X[va])
        res.append(f1_score(y[va], p, average="macro"))
        pcs.append(pd.Series(f1_score(y[va], p, average=None, labels=m.classes_), index=m.classes_))
    return (np.array(res), pd.concat(pcs, axis=1).mean(axis=1)) if per_class else np.array(res)


GROUPS = {
    "Загальні (протокол, тривалість)": ["protocol", "duration"],
    "Обсяги (пакети, байти)": ["fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "fwd_payload_bytes",
                               "bwd_payload_bytes", "fwd_data_pkts", "bwd_data_pkts", "fwd_header_bytes",
                               "bwd_header_bytes"],
    "Розміри пакетів і навантаження": [p + s for p in ("pkt_len", "fwd_pkt_len", "bwd_pkt_len", "payload",
                                                       "fwd_payload", "bwd_payload")
                                       for s in ("_min", "_max", "_mean", "_std")],
    "Швидкості й співвідношення": ["flow_bytes_s", "flow_pkts_s", "fwd_pkts_s", "bwd_pkts_s", "down_up_ratio",
                                   "bytes_ratio_fwd_bwd"],
    "Інтервали між пакетами (IAT)": [p + s for p in ("flow_iat", "fwd_iat", "bwd_iat")
                                     for s in ("_min", "_max", "_mean", "_std")],
    "Прапорці TCP": ["fin_cnt", "syn_cnt", "rst_cnt", "psh_cnt", "ack_cnt", "urg_cnt", "fwd_psh_cnt"],
    "Початкове вікно TCP": ["init_win_fwd", "init_win_bwd"],
    "Активність / простій": [p + s for p in ("active", "idle") for s in ("_min", "_max", "_mean", "_std")],
}


def group_of(f):
    return next(g for g, fs in GROUPS.items() if f in fs)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    full, feats = load(with_empty=True)
    assert sum(len(v) for v in GROUPS.values()) == len(feats) == 71
    dev_all = full[full.meta_night == 1].reset_index(drop=True)
    dev = dev_all[dev_all.meta_no_payload == 0].reset_index(drop=True)
    say(f"Набір розробки (ніч 1): {dev.meta_session.nunique()} сесій, {len(dev)} потоків з даними "
        f"(+{len(dev_all) - len(dev)} без даних)")

    # --- 0. Артефакт невдалих з'єднань ---
    say("\n[0] Артефакт: потоки без даних (SYN→RST)")
    e = dev_all[dev_all.meta_no_payload == 1]
    say(pd.crosstab(e.label, e.fwd_pkts + e.bwd_pkts <= 2).rename(columns={True: "≤2 пакети", False: ">2"}).to_string())
    f_with, pc_with = cv_f1(dev_all, feats, per_class=True)
    f_without, pc_without = cv_f1(dev, feats, per_class=True)
    say(f"RF, 71 ознака: з порожніми потоками macro-F1 = {f_with.mean():.3f}, F1(obfs4) = {pc_with['tor_obfs4']:.3f}; "
        f"без них macro-F1 = {f_without.mean():.3f}, F1(obfs4) = {pc_without['tor_obfs4']:.3f}")
    pd.DataFrame({"з порожніми": pc_with, "без порожніх": pc_without}).round(3).to_csv(OUT / "artifact_empty_flows.csv")

    # --- А. Вилучення за правилами ---
    say("\n[А] Вилучення за правилами")
    rules = []
    for f in feats:
        nun = dev[f].nunique()
        if nun <= 1:
            rules.append((f, f"стала (усі значення = {dev[f].iloc[0]})"))
    tcp = dev[dev.protocol == 6]
    say("init_win_bwd у TCP-потоках:", tcp.init_win_bwd.value_counts().to_dict())
    say("init_win_fwd у TCP-потоках за наявністю SYN від VM:")
    say(pd.crosstab(tcp.init_win_fwd.where(tcp.init_win_fwd.isin([64240, 65535]), -2),
                    tcp.syn_cnt > 0).to_string())
    rules.append(("init_win_bwd", "у TCP завжди 65535 — вікно виставляє NAT VirtualBox, а не сервер; у UDP −1 — дублює protocol"))
    rules.append(("init_win_fwd", "64240 — вікно ядра Linux у SYN, 65535 — потік-продовження (розрізаний за 120 с); "
                                  "залежить від ОС клієнта і правила розрізання, а не від анонімної мережі"))
    pd.DataFrame(rules, columns=["ознака", "причина"]).to_csv(OUT / "removed_by_rules.csv", index=False)
    for f, why in rules:
        say(f"  − {f}: {why}")
    stage_a = [f for f in feats if f not in {r[0] for r in rules}]
    say(f"Лишилось {len(stage_a)}")

    # --- Б. Кореляційний фільтр ---
    say(f"\n[Б] Кореляційний фільтр |ρ| ≥ {CORR}")
    rho = dev[stage_a].corr(method="spearman").fillna(0).abs()
    dist = squareform(1 - rho.to_numpy(), checks=False).clip(0)
    Z = linkage(dist, method="complete")              # complete: у кластері ВСІ пари мають |ρ| ≥ поріг
    cl = fcluster(Z, t=1 - CORR, criterion="distance")
    mi = pd.Series(mutual_info_classif(dev[stage_a], dev.label, random_state=SEED), index=stage_a)
    mi.sort_values(ascending=False).round(4).to_csv(OUT / "mutual_information.csv", header=["MI"])
    stage_b, clusters = [], []
    for c in sorted(set(cl)):
        mem = [f for f, k in zip(stage_a, cl) if k == c]
        keep = mi[mem].idxmax()
        stage_b.append(keep)
        if len(mem) > 1:
            clusters.append({"залишено": keep, "вилучено": ", ".join(m for m in mem if m != keep),
                             "min |ρ| у кластері": round(rho.loc[mem, mem].to_numpy().min(), 3)})
            say(f"  {keep}  ←  {[m for m in mem if m != keep]}")
    pd.DataFrame(clusters).to_csv(OUT / "correlation_clusters.csv", index=False)
    stage_b = [f for f in stage_a if f in stage_b]
    say(f"Лишилось {len(stage_b)}")

    order = leaves_list(Z)
    fig, ax = plt.subplots(figsize=(11, 10))
    names = [stage_a[i] for i in order]
    im = ax.imshow(rho.loc[names, names], cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(names)), names, rotation=90, fontsize=6)
    ax.set_yticks(range(len(names)), names, fontsize=6)
    fig.colorbar(im, ax=ax, shrink=0.7, label="|ρ| Спірмена")
    fig.tight_layout()
    fig.savefig(OUT / "correlation_matrix.png", dpi=200)
    plt.close(fig)

    # --- В. Перестановкова важливість ---
    say("\n[В] Перестановкова важливість (RF, 5 фолдів, 5 перестановок, метрика macro-F1)")
    cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
    X, y, g = dev[stage_b].to_numpy(), dev.label.to_numpy(), dev.meta_session.to_numpy()
    imps = []
    for tr, va in cv.split(X, y, g):
        m = rf().fit(X[tr], y[tr], sample_weight=compute_sample_weight("balanced", y[tr]))
        pi = permutation_importance(m, X[va], y[va], scoring="f1_macro", n_repeats=5, random_state=SEED, n_jobs=-1)
        imps.append(pi.importances_mean)
    imp = pd.DataFrame(np.array(imps).T, index=stage_b)
    rank = pd.DataFrame({"importance": imp.mean(axis=1), "std_between_folds": imp.std(axis=1),
                         "MI": mi[stage_b], "group": [group_of(f) for f in stage_b]}
                        ).sort_values("importance", ascending=False)
    rank.round(5).to_csv(OUT / "permutation_importance.csv")
    say(rank.head(15).round(4).to_string())

    top = rank.head(25)[::-1]
    fig, ax = plt.subplots(figsize=(8, 8))
    ax.barh(top.index, top.importance, xerr=top.std_between_folds, color=BLUE, height=0.6,
            error_kw={"ecolor": "#52514e", "lw": 1})
    ax.set_xlabel("Падіння macro-F1 при перемішуванні ознаки")
    ax.tick_params(axis="y", labelsize=8)
    ax.grid(axis="x", color="#e4e3df", lw=0.6)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    fig.tight_layout()
    fig.savefig(OUT / "permutation_importance.png", dpi=200)
    plt.close(fig)

    # --- Г. Крива macro-F1 від k ---
    say("\n[Г] macro-F1 від кількості найважливіших ознак (RF, групова 5-фолдова CV)")
    ranked = list(rank.index)
    ks = sorted(set(list(range(2, 21)) + list(range(22, len(ranked) + 1, 3)) + [len(ranked)]))
    curve = []
    for k in ks:
        s = cv_f1(dev, ranked[:k])
        curve.append({"k": k, "mean": s.mean(), "std": s.std(ddof=1), "se": s.std(ddof=1) / np.sqrt(len(s))})
        say(f"  k={k:2d}: {s.mean():.4f} ± {s.std(ddof=1):.4f}")
    curve = pd.DataFrame(curve)
    curve.round(4).to_csv(OUT / "f1_vs_k.csv", index=False)
    best = curve.loc[curve["mean"].idxmax()]
    k_sel = int(curve[curve["mean"] >= best["mean"] - best["se"]].k.min())
    selected = ranked[:k_sel]
    say(f"Максимум {best['mean']:.4f} при k={int(best.k)}; поріг (−1 SE) {best['mean'] - best['se']:.4f} → обрано k={k_sel}")

    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.fill_between(curve.k, curve["mean"] - curve["std"], curve["mean"] + curve["std"], color=BLUE, alpha=0.15, lw=0)
    ax.plot(curve.k, curve["mean"], color=BLUE, lw=2, marker="o", ms=4)
    ax.axhline(best["mean"] - best["se"], color="#52514e", lw=1, ls="--")
    ax.axvline(k_sel, color="#52514e", lw=1, ls=":")
    ax.annotate(f"обрано k = {k_sel}", (k_sel, curve["mean"].min()), xytext=(6, 0), textcoords="offset points",
                fontsize=9, color="#0b0b0b")
    ax.set_xlabel("Кількість ознак k (за спаданням важливості)")
    ax.set_ylabel("macro-F1 (групова CV, сеанс 1)")
    ax.grid(color="#e4e3df", lw=0.6)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    fig.tight_layout()
    fig.savefig(OUT / "f1_vs_k.png", dpi=200)
    plt.close(fig)

    # --- Д. Абляція груп (на наборі після етапу Б) ---
    say("\n[Д] Абляція груп ознак (набір після етапу Б, RF)")
    base = cv_f1(dev, stage_b)
    abl = [{"група": "— (усі після етапу Б)", "ознак": len(stage_b), "macro_f1": base.mean(), "delta": 0.0}]
    for gname, fs in GROUPS.items():
        rest = [f for f in stage_b if f not in fs]
        if len(rest) == len(stage_b):
            continue
        s = cv_f1(dev, rest)
        abl.append({"група": f"без «{gname}»", "ознак": len(rest), "macro_f1": s.mean(), "delta": s.mean() - base.mean()})
        only = [f for f in stage_b if f in fs]
        s2 = cv_f1(dev, only)
        abl.append({"група": f"лише «{gname}»", "ознак": len(only), "macro_f1": s2.mean(), "delta": s2.mean() - base.mean()})
    abl = pd.DataFrame(abl)
    abl.round(4).to_csv(OUT / "group_ablation.csv", index=False)
    say(abl.round(4).to_string(index=False))

    sel_tab = rank.loc[selected, ["importance", "MI", "group"]].reset_index(names="feature")
    sel_tab.round(5).to_csv(OUT / "selected_features.csv", index=False)
    (OUT / "selected_features.json").write_text(json.dumps(
        {"selected": selected, "after_rules": stage_a, "after_correlation": stage_b,
         "k": k_sel, "cv_macro_f1_selected": float(curve.set_index("k").loc[k_sel, "mean"]),
         "cv_macro_f1_all_after_corr": float(base.mean())}, ensure_ascii=False, indent=1))
    say(f"\nВідібрано {k_sel} ознак: {selected}")
    (OUT / "report.txt").write_text("\n".join(log) + "\n")


if __name__ == "__main__":
    main()
