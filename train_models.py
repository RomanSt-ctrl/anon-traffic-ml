#!/usr/bin/env python3
"""3.3 Порівняльна оцінка класифікаторів (журнал, п. 9.3).
  1) для кожного з 8 класифікаторів — підбір гіперпараметрів сіткою на ночі 1 (групова 3-фолдова CV за сесіями, macro-F1);
  2) навчання з найкращими параметрами на всій ночі 1, оцінка на ночі 2 (відкладений тест) у трьох задачах:
     multi — 7 класів, tech — 4 технології (clearnet/tor/i2p/vpn), binary — анонімізатор чи clearnet;
     метрики на рівні потоку і на рівні сесії (голосування потоків), час навчання і класифікації;
  3) для двох найкращих за CV моделей — матриці помилок, вплив відбору ознак (71 / 68 / відібрані),
     перевірка «навчання на 4 VM → тест на 5-й» (leave-one-VM-out) і «ніч 2 → ніч 1».
Модель-переможця обрано за CV на ночі 1, а не за тестом.
Запуск: python3 scripts/train_models.py  (≈ 15–30 хв на 24 ядрах)"""
import json
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.metrics import confusion_matrix, f1_score, roc_auc_score
from sklearn.model_selection import GridSearchCV, StratifiedGroupKFold
from sklearn.utils.class_weight import compute_sample_weight

from common import CLASSES, RES, SEED, fit, load, models, scores, selected_features, session_vote, target

OUT = RES / "3_3"
BLUE, ORANGE = "#2a78d6", "#eb6834"

GRID = {
    "Naive Bayes":         {"gaussiannb__var_smoothing": [1e-9, 1e-6, 1e-3]},
    "Logistic Regression": {"logisticregression__C": [0.1, 1, 10]},
    "k-NN":          {"kneighborsclassifier__n_neighbors": [3, 5, 11, 21],
                            "kneighborsclassifier__weights": ["uniform", "distance"]},
    "SVM (RBF)":           {"svc__C": [1, 10, 100]},
    "Decision Tree":       {"max_depth": [None, 20, 10], "min_samples_leaf": [1, 5]},
    "Random Forest":       {"max_features": ["sqrt", 0.3], "min_samples_leaf": [1, 3]},
    "Gradient Boosting":   {"learning_rate": [0.05, 0.1], "max_leaf_nodes": [31, 63]},
    "MLP":                 {"mlpclassifier__hidden_layer_sizes": [(64,), (128, 64)],
                            "mlpclassifier__alpha": [1e-4, 1e-3]},
}
log = []


def say(*a):
    s = " ".join(str(x) for x in a)
    print(s, flush=True)
    log.append(s)


def tune(name, model, sw, X, y, g):
    params = {}
    if sw:
        last = model.steps[-1][0] if hasattr(model, "steps") else None
        params = {(f"{last}__" if last else "") + "sample_weight": compute_sample_weight("balanced", y)}
    gs = GridSearchCV(model, GRID[name], scoring="f1_macro", n_jobs=6 if name in ("Random Forest", "k-NN") else -1,
                      cv=StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=SEED), refit=False)
    gs.fit(X, y, groups=g, **params)
    return gs.best_params_, gs.best_score_, gs.cv_results_["std_test_score"][gs.best_index_]


def evaluate(model, sw, tr, te, feats, task):
    Xtr, ytr = tr[feats].to_numpy(), target(tr, task)
    Xte, yte = te[feats].to_numpy(), target(te, task)
    t_fit = fit(model, sw, Xtr, ytr)
    t0 = time.perf_counter()
    p = model.predict(Xte)
    t_pred = (time.perf_counter() - t0) / len(Xte) * 1e6
    r = scores(yte, p)
    sy, sp = session_vote(te.meta_session.to_numpy(), yte, p)
    r |= {"session_macro_f1": f1_score(sy, sp, average="macro"), "session_acc": float((sy == sp).mean()),
          "fit_s": t_fit, "predict_us_per_flow": t_pred}
    if task == "binary" and hasattr(model, "predict_proba"):
        r["roc_auc"] = roc_auc_score(yte, model.predict_proba(Xte)[:, 1])
    return r, p


def plot_cm(y, p, labels, path, title_note):
    cm = confusion_matrix(y, p, labels=labels)
    cmn = cm / cm.sum(axis=1, keepdims=True)
    fig, ax = plt.subplots(figsize=(7.5, 6.5))
    im = ax.imshow(cmn, cmap="Blues", vmin=0, vmax=1)
    for i in range(len(labels)):
        for j in range(len(labels)):
            if cm[i, j]:
                ax.text(j, i, f"{cmn[i, j]:.2f}\n({cm[i, j]})", ha="center", va="center", fontsize=7,
                        color="white" if cmn[i, j] > 0.6 else "#0b0b0b")
    ax.set_xticks(range(len(labels)), labels, rotation=35, ha="right")
    ax.set_yticks(range(len(labels)), labels)
    ax.set_xlabel("Прогноз")
    ax.set_ylabel("Справжній клас")
    ax.set_title(title_note, fontsize=10)
    fig.colorbar(im, ax=ax, shrink=0.8, label="Частка рядка")
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)
    return pd.DataFrame(cm, index=labels, columns=labels)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    df, all_feats = load()
    feats = selected_features()
    rules_feats = json.loads((RES / "3_2/selected_features.json").read_text())["after_rules"]
    dev = df[df.meta_night == 1].reset_index(drop=True)
    test = df[df.meta_night == 2].reset_index(drop=True)
    say(f"Ознак: {len(feats)}; ніч 1: {len(dev)} потоків / {dev.meta_session.nunique()} сесій; "
        f"ніч 2: {len(test)} потоків / {test.meta_session.nunique()} сесій")

    # 1. Підбір гіперпараметрів
    say("\n[1] Підбір гіперпараметрів (ніч 1, 3-фолдова групова CV, macro-F1, 7 класів)")
    best, cvtab = {}, []
    X, y, g = dev[feats].to_numpy(), dev.label.to_numpy(), dev.meta_session.to_numpy()
    for name, (m, sw) in models().items():
        t0 = time.perf_counter()
        bp, bs, bstd = tune(name, m, sw, X, y, g)
        best[name] = bp
        cvtab.append({"model": name, "best_params": json.dumps(bp, default=str), "cv_macro_f1": bs, "cv_std": bstd,
                      "tuning_s": time.perf_counter() - t0})
        say(f"  {name:20s} CV macro-F1 = {bs:.4f} ± {bstd:.4f}  {bp}  ({time.perf_counter() - t0:.0f} с)")
    cvtab = pd.DataFrame(cvtab).sort_values("cv_macro_f1", ascending=False)
    cvtab.round(4).to_csv(OUT / "tuning_cv.csv", index=False)
    top2 = list(cvtab.model[:2])
    say(f"Найкращі за CV: {top2}")

    def tuned(name):
        m, sw = models()[name]
        return clone(m).set_params(**best[name]), sw

    # 2. Тест на ночі 2
    say("\n[2] Ніч 1 → ніч 2")
    rows, perclass, preds = [], [], {}
    for task in ("multi", "tech", "binary"):
        for name in models():
            m, sw = tuned(name)
            r, p = evaluate(m, sw, dev, test, feats, task)
            rows.append({"task": task, "model": name} | r)
            if task == "multi":
                preds[name] = p
                perclass.append(pd.Series(f1_score(test.label, p, average=None, labels=CLASSES), index=CLASSES, name=name))
            say(f"  {task:6s} {name:20s} F1m={r['macro_f1']:.4f} BA={r['bal_acc']:.4f} "
                f"сесії F1m={r['session_macro_f1']:.4f} acc={r['session_acc']:.4f} fit={r['fit_s']:.1f}с")
    res = pd.DataFrame(rows)
    res.round(4).to_csv(OUT / "test_night2.csv", index=False)
    perclass = pd.DataFrame(perclass)
    perclass.round(3).to_csv(OUT / "test_night2_per_class_f1.csv")
    say(perclass.round(3).to_string())

    multi = res[res.task == "multi"].set_index("model").loc[list(models())]
    fig, ax = plt.subplots(figsize=(9, 4.5))
    xx = np.arange(len(multi))
    ax.bar(xx - 0.2, multi.macro_f1, 0.38, color=BLUE, label="потік")
    ax.bar(xx + 0.2, multi.session_macro_f1, 0.38, color=ORANGE, label="сесія (голосування)")
    ax.set_xticks(xx, multi.index, rotation=25, ha="right")
    ax.set_ylabel("macro-F1, сеанс 2")
    ax.set_ylim(0, 1)
    ax.legend(frameon=False, loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=2)
    ax.grid(axis="y", color="#e4e3df", lw=0.6)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    fig.tight_layout()
    fig.savefig(OUT / "models_macro_f1.png", dpi=200)
    plt.close(fig)

    # 3. Поглиблений аналіз двох найкращих
    say("\n[3] Матриці помилок (ніч 2)")
    for name in top2:
        tag = name.split()[0].lower()
        p = preds[name]
        plot_cm(test.label, p, CLASSES, OUT / f"cm_flow_{tag}.png", f"{name}: рівень потоку").to_csv(OUT / f"cm_flow_{tag}.csv")
        sy, sp = session_vote(test.meta_session.to_numpy(), test.label.to_numpy(), p)
        plot_cm(sy, sp, CLASSES, OUT / f"cm_session_{tag}.png", f"{name}: рівень сесії").to_csv(OUT / f"cm_session_{tag}.csv")

    say("\n[3а] Вплив відбору ознак (ніч 1 → ніч 2, 7 класів)")
    fs_rows = []
    for name in top2:
        for fname, fl in (("усі 71", all_feats), (f"після правил ({len(rules_feats)})", rules_feats),
                          (f"відібрані ({len(feats)})", feats)):
            m, sw = tuned(name)
            r, _ = evaluate(m, sw, dev, test, fl, "multi")
            fs_rows.append({"model": name, "features": fname} | r)
            say(f"  {name:18s} {fname:18s} F1m={r['macro_f1']:.4f} сесії F1m={r['session_macro_f1']:.4f} "
                f"fit={r['fit_s']:.1f}с pred={r['predict_us_per_flow']:.1f}мкс")
    pd.DataFrame(fs_rows).round(4).to_csv(OUT / "feature_set_comparison.csv", index=False)

    say("\n[3б] Leave-one-VM-out (обидві ночі; навчання на 4 VM, тест на 5-й) і ніч 2 → ніч 1")
    lo_rows = []
    for name in top2:
        for vm in sorted(df.meta_vm.unique()):
            m, sw = tuned(name)
            r, _ = evaluate(m, sw, df[df.meta_vm != vm], df[df.meta_vm == vm], feats, "multi")
            lo_rows.append({"model": name, "test": f"vm{vm}"} | r)
        m, sw = tuned(name)
        r, _ = evaluate(m, sw, test, dev, feats, "multi")
        lo_rows.append({"model": name, "test": "ніч 1 (навч. ніч 2)"} | r)
    lo = pd.DataFrame(lo_rows)
    lo.round(4).to_csv(OUT / "leave_one_vm_out.csv", index=False)
    say(lo[["model", "test", "macro_f1", "bal_acc", "session_macro_f1", "session_acc"]].round(4).to_string(index=False))

    (OUT / "best_params.json").write_text(json.dumps(best, ensure_ascii=False, indent=1, default=str))
    (OUT / "report.txt").write_text("\n".join(log) + "\n")


if __name__ == "__main__":
    main()
