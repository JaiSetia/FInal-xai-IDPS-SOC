"""Time-based train/validation/test splits (never random).

Near-duplicate flows (scan bursts, DoS floods) are close together in time, so a random split
would put copies of the same flow in train and test and inflate every score. Here, train is
always strictly earlier than validation, which is strictly earlier than test.

Three modes: `class-time` (default; per day and class, earliest 60% train, then validation,
then test, with a gap around each cut), `day` (whole days) and `window` (rows by time).
After splitting, exact duplicate rows are dropped inside each split, and the share of test
rows whose feature vector also occurs in train is reported.
"""

from dataclasses import dataclass

import numpy as np
import pandas as pd

from idps.detect.data import BENIGN
from idps.features import MODEL_FEATURES

_DAY_MS = 86_400_000
# Flows last up to the active timeout (120 s), so a flow that starts this close to a cut can
# still be running on the other side of it.
DEFAULT_GAP_MS = 120_000


@dataclass
class Split:
    train: pd.DataFrame
    validation: pd.DataFrame
    test: pd.DataFrame
    description: dict


def _iso(ms: int) -> str:
    return pd.Timestamp(ms, unit="ms", tz="UTC").isoformat()


def _describe(mode: str, parts: dict[str, pd.DataFrame], extra: dict) -> dict:
    out = {"mode": mode, **extra, "parts": {}}
    for name, df in parts.items():
        lo, hi = int(df["start_ms"].min()), int(df["start_ms"].max())
        out["parts"][name] = {
            "rows": len(df), "first_start_ms": lo, "last_start_ms": hi,
            "first_start": _iso(lo), "last_start": _iso(hi),
            "class_counts": {str(k): int(v) for k, v in df["label"].value_counts().items()},
        }
    return out


def _identical_to_train(train: pd.DataFrame, part: pd.DataFrame, features: list[str]) -> dict:
    """How many rows of `part` have a feature vector identical to some train row."""
    seen = train[features].drop_duplicates().assign(_in_train=True)
    hit = part[features].merge(seen, on=features, how="left")["_in_train"].notna()
    return {"rows": int(hit.sum()), "share": float(hit.mean()) if len(part) else 0.0}


def _finish(mode: str, tr, va, te, extra: dict, allow_unseen_test_classes: bool = False,
            drop_duplicates: bool = True, features: list[str] | None = None,
            dropped_by_gap: dict | None = None) -> Split:
    features = list(features or MODEL_FEATURES)
    dup_cols = [*MODEL_FEATURES, "label"]
    dups = {}
    if drop_duplicates:
        out = []
        for name, df in (("train", tr), ("validation", va), ("test", te)):
            kept = df.drop_duplicates(subset=dup_cols)
            dups[name] = len(df) - len(kept)
            out.append(kept)
        tr, va, te = out
    for name, df in (("train", tr), ("validation", va), ("test", te)):
        if df.empty:
            raise ValueError(f"{mode} split left the {name} part empty; {extra}")
    classes_all = set(tr["label"]) | set(va["label"]) | set(te["label"])
    missing_train = sorted(classes_all - set(tr["label"]))
    if missing_train and not allow_unseen_test_classes:
        raise ValueError(
            f"class(es) {missing_train} are in the validation/test data but not in the "
            f"training split ({mode} split, {extra}); choose other boundaries or add data, "
            f"or pass allow_unseen_test_classes (--allow-unseen-test-classes) for a "
            f"leave-one-day-out experiment")
    if BENIGN not in set(tr["label"]):
        raise ValueError(f"no {BENIGN} rows in the training split ({mode} split)")
    parts = {"train": tr, "validation": va, "test": te}
    extra = {**extra, "allow_unseen_test_classes": allow_unseen_test_classes,
             "duplicates_dropped": dups if drop_duplicates else None,
             "train_overlap_features": features}
    if dropped_by_gap is not None:
        extra["dropped_by_gap"] = dropped_by_gap
    desc = _describe(mode, parts, extra)
    desc["identical_to_train"] = {"validation": _identical_to_train(tr, va, features),
                                  "test": _identical_to_train(tr, te, features)}
    return Split(tr.reset_index(drop=True), va.reset_index(drop=True),
                 te.reset_index(drop=True), desc)


def split_by_class_time(df: pd.DataFrame, val_frac: float = 0.2, test_frac: float = 0.2,
                        gap_ms: int = DEFAULT_GAP_MS, allow_unseen_test_classes: bool = False,
                        drop_duplicates: bool = True,
                        features: list[str] | None = None) -> Split:
    """Per (UTC day, label) group, sorted by start_ms: the first 1 - val - test of the rows
    (default 60%) are train, the next `val_frac` validation, the last `test_frac` test. Rows
    that start less than `gap_ms` from a cut (the start time of the first row after it) are
    dropped, so no train flow can still be running when a test flow begins.

    This suits CIC-IDS2017, where most attack types occur on a single day: every class
    is then in train and is tested on later traffic of the same class. The cost is that
    train and test come from the same day and attack tool, so scores are optimistic about
    new attack tools or days; use --split day with allow_unseen_test_classes for that.
    """
    if val_frac <= 0 or test_frac <= 0 or val_frac + test_frac >= 1:
        raise ValueError("val_frac and test_frac must be > 0 and sum to < 1")
    if gap_ms < 0:
        raise ValueError("gap_ms must not be negative")
    t = df["start_ms"].astype("int64").to_numpy()
    day = t // _DAY_MS
    keys = pd.DataFrame({"day": day, "label": df["label"].astype(str).to_numpy(), "t": t})
    part = np.full(len(df), -1)  # 0 train, 1 validation, 2 test, -1 dropped by the gap
    dropped: dict[str, int] = {}
    for (_, label), group in keys.groupby(["day", "label"], sort=False):
        rows = group.sort_values("t", kind="stable").index.to_numpy()
        n, tt = len(rows), t[rows]
        i1, i2 = int(n * (1 - val_frac - test_frac)), int(n * (1 - test_frac))
        b1, b2 = tt[i1], tt[i2]  # i2 <= n - 1 because test_frac > 0
        idx = np.arange(n)
        grp = np.where(idx < i1, 0, np.where(idx < i2, 1, 2))
        near = (np.abs(tt - b1) < gap_ms) | (np.abs(tt - b2) < gap_ms)
        grp[near] = -1
        part[rows] = grp
        if near.any():
            dropped[label] = dropped.get(label, 0) + int(near.sum())
    pick = lambda k: df[part == k].sort_values("start_ms", kind="stable")
    extra = {"val_frac": val_frac, "test_frac": test_frac, "train_frac": 1 - val_frac - test_frac,
             "gap_ms": gap_ms}
    return _finish("class-time", pick(0), pick(1), pick(2), extra, allow_unseen_test_classes,
                   drop_duplicates, features,
                   {"total": int((part == -1).sum()), "per_class": dropped})


def split_by_day(df: pd.DataFrame, val_days: int = 1, test_days: int = 1,
                 allow_unseen_test_classes: bool = False, drop_duplicates: bool = True,
                 features: list[str] | None = None) -> Split:
    """Last `test_days` calendar days (UTC, from start_ms) are test, the `val_days` before
    them validation, everything earlier is train. Days without data are ignored."""
    if val_days < 1 or test_days < 1:
        raise ValueError("val_days and test_days must be at least 1")
    day = df["start_ms"].astype("int64") // _DAY_MS
    days = sorted(day.unique())
    if len(days) < val_days + test_days + 1:
        raise ValueError(
            f"need at least {val_days + test_days + 1} distinct UTC days for a day split, "
            f"found {len(days)}; use --split window instead")
    test_set = days[-test_days:]
    val_set = days[-(test_days + val_days):-test_days]
    train_set = days[:-(test_days + val_days)]
    fmt = lambda ds: [str(pd.Timestamp(int(d) * _DAY_MS, unit="ms").date()) for d in ds]
    return _finish("day", df[day.isin(train_set)], df[day.isin(val_set)], df[day.isin(test_set)],
                   {"train_days": fmt(train_set), "validation_days": fmt(val_set),
                    "test_days": fmt(test_set)}, allow_unseen_test_classes, drop_duplicates,
                   features)


def split_by_window(df: pd.DataFrame, val_frac: float = 0.2, test_frac: float = 0.2,
                    allow_unseen_test_classes: bool = False, drop_duplicates: bool = True,
                    features: list[str] | None = None) -> Split:
    """Sort by start_ms and cut into three contiguous windows with about the given row
    fractions. Cuts fall on a start_ms value; rows with the same start_ms stay together
    (they go to the later window)."""
    if val_frac <= 0 or test_frac <= 0 or val_frac + test_frac >= 1:
        raise ValueError("val_frac and test_frac must be > 0 and sum to < 1")
    t = df["start_ms"].astype("int64")
    s = t.sort_values().to_numpy()
    n = len(s)
    if n < 3:
        raise ValueError("too few rows to split")
    cut_val = int(s[int(n * (1 - val_frac - test_frac))])
    cut_test = int(s[min(int(n * (1 - test_frac)), n - 1)])
    extra = {"val_frac": val_frac, "test_frac": test_frac,
             "validation_starts_ms": cut_val, "test_starts_ms": cut_test,
             "validation_starts": _iso(cut_val), "test_starts": _iso(cut_test)}
    return _finish("window", df[t < cut_val], df[(t >= cut_val) & (t < cut_test)],
                   df[t >= cut_test], extra, allow_unseen_test_classes, drop_duplicates, features)
