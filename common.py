"""Спільне для розділу 3 (3.2–3.4): завантаження потоків, розбиття, класифікатори, метрики.
Схема оцінювання (журнал, п. 9):
  ніч 1 — набір розробки (відбір ознак, підбір гіперпараметрів, групова CV за сесіями);
  ніч 2 — відкладений тестовий набір (ним нічого не налаштовується).
Ознаки й мітки — з data/flows/flows.csv; стовпці meta_* ознаками не є."""
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, balanced_accuracy_score, f1_score
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.utils.class_weight import compute_sample_weight

ROOT = Path(__file__).resolve().parent.parent
FLOWS = ROOT / "data/flows/flows.csv"
RES = ROOT / "results"
SEED = 42

CLASSES = ["clearnet", "i2p", "tor_obfs4", "tor_plain", "tor_snowflake", "tor_webtunnel", "vpn"]
TECH = {"clearnet": "clearnet", "i2p": "i2p", "vpn": "vpn", "tor_plain": "tor",
        "tor_obfs4": "tor", "tor_snowflake": "tor", "tor_webtunnel": "tor"}


def load(path=FLOWS, with_empty=False):
    """Потоки з даними (без невдалих з'єднань SYN→RST, журнал п. 7.4) і список усіх 71 ознаки."""
    df = pd.read_csv(path)
    if not with_empty:
        df = df[df.meta_no_payload == 0].reset_index(drop=True)
    feats = [c for c in df.columns if not c.startswith("meta_") and c != "label"]
    return df, feats


def selected_features():
    return json.loads((RES / "3_2/selected_features.json").read_text())["selected"]


def target(df, task):
    """multi — 7 класів; tech — технологія (clearnet/tor/i2p/vpn); binary — анонімізатор (1) чи clearnet (0)."""
    if task == "multi":
        return df.label.to_numpy()
    if task == "tech":
        return df.label.map(TECH).to_numpy()
    return (df.label != "clearnet").astype(int).to_numpy()


def log_scaled(model):
    """Ознаки мають важкі хвости (байти, тривалості) — для лінійних і метричних моделей log1p + стандартизація."""
    return make_pipeline(FunctionTransformer(np.log1p), StandardScaler(), model)


def models():
    """Порівнювані класифікатори. sw — чи приймає fit ваги зразків (для компенсації дисбалансу класів)."""
    return {
        "Naive Bayes":         (log_scaled(GaussianNB()), True),
        "Logistic Regression": (log_scaled(LogisticRegression(C=1.0, max_iter=3000)), True),
        "k-NN":          (log_scaled(KNeighborsClassifier(n_neighbors=5, n_jobs=-1)), False),
        "SVM (RBF)":           (log_scaled(SVC(C=10, gamma="scale", cache_size=2000)), True),
        "Decision Tree":       (DecisionTreeClassifier(min_samples_leaf=2, random_state=SEED), True),
        "Random Forest":       (RandomForestClassifier(n_estimators=300, min_samples_leaf=1, n_jobs=-1,
                                                       random_state=SEED), True),
        "Gradient Boosting":   (HistGradientBoostingClassifier(max_iter=400, learning_rate=0.1,
                                                               random_state=SEED), True),
        "MLP":                 (log_scaled(MLPClassifier(hidden_layer_sizes=(128, 64), max_iter=400,
                                                         early_stopping=True, random_state=SEED)), True),
    }


def fit(model, sw, X, y):
    """Навчання з вагами balanced: внесок кожного класу однаковий, хоч потоків clearnet у 100 разів більше, ніж vpn."""
    t0 = time.perf_counter()
    if sw:
        w = compute_sample_weight("balanced", y)
        name = model.steps[-1][0] if hasattr(model, "steps") else None
        model.fit(X, y, **({f"{name}__sample_weight": w} if name else {"sample_weight": w}))
    else:
        model.fit(X, y)
    return time.perf_counter() - t0


def scores(y, p):
    return {"macro_f1": f1_score(y, p, average="macro"), "bal_acc": balanced_accuracy_score(y, p),
            "acc": accuracy_score(y, p)}


def session_vote(sessions, y_true, y_pred):
    """Рівень сесії: мітка сесії — найчастіший прогноз серед її потоків (більшість голосів)."""
    t = pd.DataFrame({"s": sessions, "y": y_true, "p": y_pred})
    g = t.groupby("s").agg(y=("y", "first"), p=("p", lambda s: s.value_counts().idxmax()))
    return g.y.to_numpy(), g.p.to_numpy()
