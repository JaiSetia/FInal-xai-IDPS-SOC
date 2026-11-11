"""Train + evaluate + bundle in one call."""

import pandas as pd

from idps.detect.bundle import Bundle
from idps.detect.data import SEED
from idps.detect.evaluate import evaluate_anomaly, evaluate_classifier
from idps.detect.models import select_features, train_all
from idps.detect.split import (
    DEFAULT_GAP_MS,
    Split,
    split_by_class_time,
    split_by_day,
    split_by_window,
)

SPLIT_MODES = ("class-time", "day", "window")


def make_split(df: pd.DataFrame, mode: str, val: float | None = None,
               test: float | None = None, *, gap_ms: int = DEFAULT_GAP_MS,
               allow_unseen_test_classes: bool = False, drop_duplicates: bool = True,
               features: list[str] | None = None) -> Split:
    """`val`/`test`: number of days for the day split (default 1 each), fractions of rows
    for class-time and window (default 0.2 each). `gap_ms` only applies to class-time."""
    common = {"allow_unseen_test_classes": allow_unseen_test_classes,
              "drop_duplicates": drop_duplicates, "features": features}
    if mode == "class-time":
        return split_by_class_time(df, val_frac=0.2 if val is None else float(val),
                                   test_frac=0.2 if test is None else float(test),
                                   gap_ms=gap_ms, **common)
    if mode == "day":
        return split_by_day(df, val_days=1 if val is None else int(val),
                            test_days=1 if test is None else int(test), **common)
    if mode == "window":
        return split_by_window(df, val_frac=0.2 if val is None else float(val),
                               test_frac=0.2 if test is None else float(test), **common)
    raise ValueError(f"unknown split mode {mode!r}; choose from {SPLIT_MODES}")


def _metrics_for(trained, part: pd.DataFrame) -> dict:
    X = part[trained.features]
    classes = list(trained.label_encoder.classes_)
    pred = trained.label_encoder.inverse_transform(trained.model.predict(X).astype(int))
    res = evaluate_classifier(part["label"], pred, trained.model.predict_proba(X), classes)
    if trained.anomaly is not None:
        from idps.detect.models import anomaly_flags, anomaly_scores
        res["anomaly"] = evaluate_anomaly(part["label"], anomaly_scores(trained.anomaly, X),
                                          anomaly_flags(trained.anomaly, X))
    return res


def train_bundle(df: pd.DataFrame, meta: dict, model: str = "xgboost",
                 split: str = "class-time",
                 drop_features: list[str] | tuple[str, ...] = (), val: float | None = None,
                 test: float | None = None, seed: int = SEED, *, gap_ms: int = DEFAULT_GAP_MS,
                 allow_unseen_test_classes: bool = False,
                 drop_duplicates: bool = True) -> tuple[Bundle, dict]:
    """Split by time, train on the train split, evaluate on validation and test.

    Exact duplicate rows are dropped inside each split (drop_duplicates=False keeps them),
    and each part's metrics carry `train_overlap`: how many of its rows have a feature
    vector identical to a train row.

    Returns (bundle, report). The report holds the validation and test metrics.
    """
    features = select_features(drop_features)
    sp = make_split(df, split, val, test, gap_ms=gap_ms,
                    allow_unseen_test_classes=allow_unseen_test_classes,
                    drop_duplicates=drop_duplicates, features=features)
    trained = train_all(model, sp.train, features, seed)
    metrics = {"validation": _metrics_for(trained, sp.validation),
               "test": _metrics_for(trained, sp.test)}
    for part in ("validation", "test"):
        metrics[part]["train_overlap"] = sp.description["identical_to_train"][part]
    bundle = Bundle(model_name=model, model=trained.model, label_encoder=trained.label_encoder,
                    features=features, extraction_meta=meta, split=sp.description,
                    metrics=metrics, anomaly=trained.anomaly)
    report = {"model": model, "features": features, "dropped_features": list(drop_features),
              "seed": seed, "split": sp.description, "metrics": metrics,
              "versions": bundle.versions}
    return bundle, report
