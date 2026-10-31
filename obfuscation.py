#!/usr/bin/env python3
"""3.4 Стійкість класифікації до засобів обфускації (журнал, п. 9.4).
Модель — переможець 3.3 (найкраща за CV на ночі 1) з її гіперпараметрами, ознаки — відібрані в 3.2.
Навчання — ніч 1, тест — ніч 2.
  E1. Реальні транспорти Tor (obfs4, Snowflake, WebTunnel): за що їх приймає модель 7 класів і детектор «анонімізатор/clearnet».
  E2. Невідома обфускація: детектор і модель технологій навчено БЕЗ транспорту X (або без усіх трьох) —
      чи розпізнає він X як анонімізатор / як Tor.
  E3. Синтетичне маскування (доповнення пакетів, затримки — data/flows_obf/<режим>/, scripts/extract_flows.py):
      а) статична модель (навчена на звичайному трафіку) проти маскованого тесту;
      б) адаптивна модель (навчена на маскованому трафіку ночі 1); накладні витрати маскування в байтах.
Запуск (після select_features.py, train_models.py і 4 запусків extract_flows.py з режимами):
  python3 scripts/obfuscation.py"""
import json

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.metrics import f1_score

from common import CLASSES, RES, ROOT, fit, load, models, scores, selected_features, session_vote, target

OUT = RES / "3_4"
PTS = ["tor_obfs4", "tor_snowflake", "tor_webtunnel"]
MODES = ["pad_rand", "pad_mtu", "jitter", "pad_mtu+jitter"]
BLUE, ORANGE = "#2a78d6", "#eb6834"
log = []


def say(*a):
    s = " ".join(str(x) for x in a)
    print(s, flush=True)
    log.append(s)


def winner():
    tab = pd.read_csv(RES / "3_3/tuning_cv.csv")
    name = tab.sort_values("cv_macro_f1", ascending=False).model.iloc[0]
    params = json.loads((RES / "3_3/best_params.json").read_text())[name]
    params = {k: (tuple(v) if isinstance(v, list) else v) for k, v in params.items()}
    return name, params


def make(name, params):
    m, sw = models()[name]
    return clone(m).set_params(**params), sw


def share(pred):
    return pd.Series(pred).value_counts(normalize=True)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    df, _ = load()
    feats = selected_features()
    name, params = winner()
    say(f"Модель: {name} {params}; ознак: {len(feats)}")
    dev, test = df[df.meta_night == 1], df[df.meta_night == 2]

    # E1
    say("\n[E1] Реальні транспорти: розподіл прогнозів (ніч 2, частка потоків / частка сесій)")
    rows = []
    for task in ("multi", "tech", "binary"):
        m, sw = make(name, params)
        fit(m, sw, dev[feats].to_numpy(), target(dev, task))
        p = m.predict(test[feats].to_numpy())
        for cls in ["tor_plain"] + PTS:
            mask = (test.label == cls).to_numpy()
            fl = share(p[mask])
            _, sp = session_vote(test.meta_session[mask].to_numpy(), p[mask], p[mask])
            ss = share(sp)
            for k in sorted(set(fl.index) | set(ss.index), key=str):
                rows.append({"task": task, "class": cls, "predicted": k, "flows": fl.get(k, 0.0), "sessions": ss.get(k, 0.0)})
    e1 = pd.DataFrame(rows)
    e1.round(4).to_csv(OUT / "e1_transports.csv", index=False)
    say(e1[e1.flows + e1.sessions > 0.005].round(3).to_string(index=False))

    # E2
    say("\n[E2] Невідома обфускація: навчання без транспорту X")
    rows = []
    for held in [[x] for x in PTS] + [PTS]:
        tr = dev[~dev.label.isin(held)]
        for task in ("binary", "tech"):
            m, sw = make(name, params)
            fit(m, sw, tr[feats].to_numpy(), target(tr, task))
            want = 1 if task == "binary" else "tor"
            for cls in held + ["clearnet"]:
                te = test[test.label == cls]
                p = m.predict(te[feats].to_numpy())
                _, sp = session_vote(te.meta_session.to_numpy(), p, p)
                r = {"held_out": "+".join(h.removeprefix("tor_") for h in held), "task": task, "test_class": cls}
                if cls == "clearnet":
                    r |= {"flows_as_target": float((p != (0 if task == "binary" else "clearnet")).mean()),
                          "sessions_as_target": float((sp != (0 if task == "binary" else "clearnet")).mean()),
                          "note": "хибна тривога (clearnet не як clearnet)"}
                else:
                    r |= {"flows_as_target": float((p == want).mean()), "sessions_as_target": float((sp == want).mean()),
                          "note": "виявлено" + (" як анонімізатор" if task == "binary" else " як Tor"),
                          "top_other": ", ".join(f"{k}:{v:.2f}" for k, v in share(p).items() if k != want),
                          "sessions_predicted": ", ".join(f"{k}:{v:.2f}" for k, v in share(sp).items())}
                rows.append(r)
    e2 = pd.DataFrame(rows)
    e2.round(4).to_csv(OUT / "e2_unseen_transport.csv", index=False)
    say(e2.round(3).to_string(index=False))

    # E3
    say("\n[E3] Синтетичне маскування (усі класи, крім clearnet)")
    base_m = {}
    for task in ("multi", "binary"):
        m, sw = make(name, params)
        fit(m, sw, dev[feats].to_numpy(), target(dev, task))
        base_m[task] = m
    rows = []

    def measure(m, te, task):
        p = m.predict(te[feats].to_numpy())
        y = target(te, task)
        r = scores(y, p)
        sy, sp = session_vote(te.meta_session.to_numpy(), y, p)
        r["session_macro_f1"] = f1_score(sy, sp, average="macro")
        if task == "binary":
            r |= {"recall_anon": float(p[y == 1].mean()), "fpr_clearnet": float(p[y == 0].mean()),
                  "session_recall_anon": float(sp[sy == 1].mean()), "session_fpr": float(sp[sy == 0].mean())}
        return r

    for task in ("multi", "binary"):
        rows.append({"mode": "none", "model": "статична", "task": task} | measure(base_m[task], test, task))
    overhead = {}
    for mode in MODES:
        d = ROOT / f"data/flows_obf/{mode}"
        odf, _ = load(d / "flows.csv")
        ses = pd.read_csv(d / "sessions.csv")
        overhead[mode] = ses["drop_obf_added_bytes"].sum() / ses["drop_obf_orig_bytes"].sum()
        odev, otest = odf[odf.meta_night == 1], odf[odf.meta_night == 2]
        for task in ("multi", "binary"):
            rows.append({"mode": mode, "model": "статична", "task": task} | measure(base_m[task], otest, task))
            m, sw = make(name, params)
            fit(m, sw, odev[feats].to_numpy(), target(odev, task))
            rows.append({"mode": mode, "model": "адаптивна", "task": task} | measure(m, otest, task))
    e3 = pd.DataFrame(rows)
    e3["overhead_bytes"] = e3["mode"].map(overhead).fillna(0.0)
    e3.round(4).to_csv(OUT / "e3_synthetic.csv", index=False)
    say(e3.drop(columns=["acc"]).round(3).to_string(index=False))

    mm = e3[e3.task == "multi"]
    labels = ["none"] + MODES
    st = [mm[(mm["mode"] == k) & (mm.model == "статична")].macro_f1.iloc[0] for k in labels]
    ad = [np.nan] + [mm[(mm["mode"] == k) & (mm.model == "адаптивна")].macro_f1.iloc[0] for k in MODES]
    fig, ax = plt.subplots(figsize=(8.5, 4.5))
    xx = np.arange(len(labels))
    ax.bar(xx - 0.2, st, 0.38, color=BLUE, label="статична модель (навчена без маскування)")
    ax.bar(xx + 0.2, ad, 0.38, color=ORANGE, label="адаптивна модель (навчена на маскованому)")
    names = {"none": "без маскування", "pad_rand": "випадкове\nдоповнення", "pad_mtu": "доповнення\nдо 1400 Б",
             "jitter": "затримки\n0–50 мс", "pad_mtu+jitter": "доповнення\n+ затримки"}
    ax.set_xticks(xx, [names[k] + (f"\n(+{overhead[k] * 100:.0f} % байтів)" if k in overhead and overhead[k] else "")
                       for k in labels], fontsize=8)
    ax.set_ylabel("macro-F1, 7 класів, сеанс 2")
    ax.set_ylim(0, 1)
    ax.legend(frameon=False, fontsize=8, loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=2)
    ax.grid(axis="y", color="#e4e3df", lw=0.6)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    fig.tight_layout()
    fig.savefig(OUT / "e3_synthetic.png", dpi=200)
    plt.close(fig)

    (OUT / "report.txt").write_text("\n".join(log) + "\n")


if __name__ == "__main__":
    main()
