#!/usr/bin/env python3
"""Додаткові перевірки достовірності розділу 3 (журнал, п. 9.5):
  R1. Крива навчання: Gradient Boosting на 10…100 % сесій ночі 1 (стратифіковано за класами, 5 повторів) → тест на ночі 2.
      Відповідає на питання «чи достатньо зібраних даних».
  R2. Невідомий міст WebTunnel: усі сесії WebTunnel ходили на обидва мости (A і B). Модель навчено на ночі 1 без потоків
      до моста X, тест — потоки ночі 2 до моста X. Чи модель вивчила протокол, а не конкретний сервер.
      Адреси мостів у звіт не пишуться (лише «міст A/B»).
  R3. Довірчі інтервали: бутстреп за сесіями ночі 2 (1000 повторів) для macro-F1 усіх 8 класифікаторів
      і для різниці Gradient Boosting − Random Forest.
Запуск (після train_models.py): python3 scripts/robustness.py"""
import json

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.metrics import f1_score

from common import RES, SEED, fit, load, models, selected_features, session_vote

OUT = RES / "3_5"
BLUE = "#2a78d6"
log = []


def say(*a):
    s = " ".join(str(x) for x in a)
    print(s, flush=True)
    log.append(s)


def tuned(name):
    params = json.loads((RES / "3_3/best_params.json").read_text())[name]
    m, sw = models()[name]
    return clone(m).set_params(**{k: (tuple(v) if isinstance(v, list) else v) for k, v in params.items()}), sw


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    df, _ = load()
    feats = selected_features()
    dev, test = df[df.meta_night == 1], df[df.meta_night == 2]
    Xte, yte = test[feats].to_numpy(), test.label.to_numpy()

    # R1
    say("[R1] Крива навчання (Gradient Boosting, 7 класів, тест — ніч 2)")
    ses = dev.groupby("meta_session").label.first()
    rows = []
    for frac in (0.1, 0.25, 0.5, 0.75, 1.0):
        for rep in range(5 if frac < 1 else 1):
            pick = ses.groupby(ses).sample(frac=frac, random_state=SEED + rep).index if frac < 1 else ses.index
            tr = dev[dev.meta_session.isin(pick)]
            m, sw = tuned("Gradient Boosting")
            fit(m, sw, tr[feats].to_numpy(), tr.label.to_numpy())
            p = m.predict(Xte)
            sy, sp = session_vote(test.meta_session.to_numpy(), yte, p)
            rows.append({"frac": frac, "rep": rep, "sessions": len(pick), "flows": len(tr),
                         "macro_f1": f1_score(yte, p, average="macro"), "session_acc": float((sy == sp).mean())})
    lc = pd.DataFrame(rows)
    lc.round(4).to_csv(OUT / "r1_learning_curve.csv", index=False)
    agg = lc.groupby("frac").agg(sessions=("sessions", "mean"), f1=("macro_f1", "mean"), f1_std=("macro_f1", "std"),
                                 s_acc=("session_acc", "mean"), s_acc_min=("session_acc", "min"))
    say(agg.round(4).to_string())
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.errorbar(agg.sessions, agg.f1, yerr=agg.f1_std.fillna(0), color=BLUE, lw=2, marker="o", ms=5, capsize=3)
    ax.set_xlabel("Сесій сеансу 1 у навчанні")
    ax.set_ylabel("macro-F1 (потік), сеанс 2")
    ax.set_ylim(0.8, 1.0)
    ax.grid(color="#e4e3df", lw=0.6)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    fig.tight_layout()
    fig.savefig(OUT / "r1_learning_curve.png", dpi=200)
    plt.close(fig)

    # R2
    say("\n[R2] Невідомий міст WebTunnel (потоки до моста X вилучено з навчання)")
    wt = df.label == "tor_webtunnel"
    ips = sorted(df[wt].meta_remote_ip.value_counts().index[:2])
    rows = []
    for name, ip in zip("AB", ips):
        tr = dev[~((dev.label == "tor_webtunnel") & (dev.meta_remote_ip == ip))]
        te = test[(test.label == "tor_webtunnel") & (test.meta_remote_ip == ip)]
        m, sw = tuned("Gradient Boosting")
        fit(m, sw, tr[feats].to_numpy(), tr.label.to_numpy())
        p = pd.Series(m.predict(te[feats].to_numpy()))
        share = p.value_counts(normalize=True)
        tor_like = share[share.index.str.startswith("tor_")].sum()
        rows.append({"bridge": name, "train_webtunnel_flows": int((tr.label == "tor_webtunnel").sum()),
                     "test_flows": len(te), "as_webtunnel": share.get("tor_webtunnel", 0.0), "as_any_tor": tor_like,
                     "other": ", ".join(f"{k}:{v:.3f}" for k, v in share.items() if k != "tor_webtunnel")})
    # контроль: той самий міст присутній у навчанні
    m, sw = tuned("Gradient Boosting")
    fit(m, sw, dev[feats].to_numpy(), dev.label.to_numpy())
    for name, ip in zip("AB", ips):
        te = test[(test.label == "tor_webtunnel") & (test.meta_remote_ip == ip)]
        p = pd.Series(m.predict(te[feats].to_numpy()))
        rows.append({"bridge": f"{name} (контроль: міст є в навчанні)", "test_flows": len(te),
                     "as_webtunnel": float((p == "tor_webtunnel").mean()), "as_any_tor": float(p.str.startswith("tor_").mean())})
    r2 = pd.DataFrame(rows)
    r2.round(4).to_csv(OUT / "r2_webtunnel_bridge.csv", index=False)
    say(r2.round(3).to_string(index=False))

    # R3
    say("\n[R3] 95 % довірчі інтервали macro-F1 (бутстреп за сесіями ночі 2, 1000 повторів)")
    preds = {}
    for name in models():
        m, sw = tuned(name)
        fit(m, sw, dev[feats].to_numpy(), dev.label.to_numpy())
        preds[name] = m.predict(Xte)
    sess = test.meta_session.to_numpy()
    uniq = np.unique(sess)
    idx_of = {s: np.flatnonzero(sess == s) for s in uniq}
    by_label = pd.Series(test.groupby("meta_session").label.first())
    rng = np.random.default_rng(SEED)
    boot = {n: [] for n in preds}
    diff = []
    for _ in range(1000):
        # стратифікований бутстреп: сесії кожного класу вибираються з поверненням у тій самій кількості
        pick = np.concatenate([rng.choice(g.index.to_numpy(), size=len(g), replace=True) for _, g in by_label.groupby(by_label)])
        ix = np.concatenate([idx_of[s] for s in pick])
        f = {n: f1_score(yte[ix], p[ix], average="macro") for n, p in preds.items()}
        for n in preds:
            boot[n].append(f[n])
        diff.append(f["Gradient Boosting"] - f["Random Forest"])
    rows = []
    for n, v in boot.items():
        v = np.array(v)
        rows.append({"model": n, "macro_f1": f1_score(yte, preds[n], average="macro"),
                     "ci_low": np.percentile(v, 2.5), "ci_high": np.percentile(v, 97.5)})
    ci = pd.DataFrame(rows).sort_values("macro_f1", ascending=False)
    d = np.array(diff)
    ci.round(4).to_csv(OUT / "r3_bootstrap_ci.csv", index=False)
    say(ci.round(3).to_string(index=False))
    say(f"GB − RF: {np.mean(d):.4f}, 95 % ДІ [{np.percentile(d, 2.5):.4f}; {np.percentile(d, 97.5):.4f}], "
        f"частка повторів, де GB > RF: {(d > 0).mean():.3f}")
    (OUT / "report.txt").write_text("\n".join(log) + "\n")


if __name__ == "__main__":
    main()
