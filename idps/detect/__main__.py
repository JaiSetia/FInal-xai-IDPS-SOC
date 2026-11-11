"""CLI: python -m idps.detect train labelled.parquet [more ...] --model xgboost|rf|mlp
                 --split class-time|day|window -o models/model.joblib --report reports/metrics.json
         python -m idps.detect evaluate <bundle> <labelled.parquet> [--report out.json]"""

import argparse
import json
import sys

from idps.detect.bundle import DEFAULT_MODEL_PATH, load_bundle, save_bundle
from idps.detect.data import SEED, load_labelled
from idps.detect.evaluate import evaluate_bundle, write_report
from idps.detect.models import MODEL_NAMES
from idps.detect.split import DEFAULT_GAP_MS
from idps.detect.train import SPLIT_MODES, train_bundle


def _brief(m: dict) -> str:
    fpr = m["benign_false_positive_rate"]
    ov = m.get("train_overlap")
    overlap = "" if ov is None else f", {ov['share']:.1%} of rows identical to a train row"
    return (f"macro-F1 {m['macro_f1']:.3f}, accuracy {m['accuracy']:.3f}, "
            f"BENIGN FPR {'n/a' if fpr is None else f'{fpr:.4f}'}{overlap}")


def _train(args: argparse.Namespace) -> int:
    df, meta = load_labelled(args.inputs, allow_low_match=args.allow_low_match_rate)
    bundle, report = train_bundle(
        df, meta, model=args.model, split=args.split, drop_features=args.drop_feature,
        val=args.val, test=args.test, seed=args.seed, gap_ms=args.gap_ms,
        allow_unseen_test_classes=args.allow_unseen_test_classes,
        drop_duplicates=not args.keep_duplicates)
    save_bundle(bundle, args.output)
    print(f"{len(df)} rows, split={args.split}, model={args.model} -> {args.output}",
          file=sys.stderr)
    print(f"validation: {_brief(report['metrics']['validation'])}", file=sys.stderr)
    print(f"test:       {_brief(report['metrics']['test'])}", file=sys.stderr)
    if args.report:
        write_report(report, args.report)
        print(f"report -> {args.report}", file=sys.stderr)
    return 0


def _evaluate(args: argparse.Namespace) -> int:
    df, meta = load_labelled([args.data], allow_low_match=args.allow_low_match_rate)
    bundle = load_bundle(args.bundle, live_meta=meta, live_columns=list(df.columns))
    result = evaluate_bundle(bundle, df, meta)
    if args.report:
        write_report(result, args.report)
    print(json.dumps({k: result[k] for k in ("n", "accuracy", "macro_f1",
                                             "benign_false_positive_rate")}, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m idps.detect")
    sub = parser.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("train", help="train a model on labelled feature files")
    t.add_argument("inputs", nargs="+", help="labelled parquet file(s) from 'features label'")
    t.add_argument("--model", choices=MODEL_NAMES, default="xgboost")
    t.add_argument("--split", choices=SPLIT_MODES, default="class-time",
                   help="class-time (default; recommended for CIC-IDS2017), day or window")
    t.add_argument("--val", type=float, default=None,
                   help="validation size: number of days (day split, default 1) or "
                        "fraction of rows (class-time and window, default 0.2)")
    t.add_argument("--test", type=float, default=None,
                   help="test size: number of days (default 1) or fraction (default 0.2)")
    t.add_argument("--gap-ms", type=int, default=DEFAULT_GAP_MS,
                   help="class-time: drop rows starting this close to a cut (default 120000, "
                        "the active timeout)")
    t.add_argument("--allow-unseen-test-classes", action="store_true",
                   help="do not require every validation/test class to be in train "
                        "(leave-one-day-out experiments)")
    t.add_argument("--keep-duplicates", action="store_true",
                   help="do not drop exact duplicate rows within each split")
    t.add_argument("--allow-low-match-rate", action="store_true",
                   help="train on label files whose match rate is below 50% or unknown")
    t.add_argument("--drop-feature", action="append", default=[], metavar="NAME",
                   help="exclude a model feature, e.g. dst_port (repeatable)")
    t.add_argument("--seed", type=int, default=SEED)
    t.add_argument("-o", "--output", default=DEFAULT_MODEL_PATH)
    t.add_argument("--report", default=None, help="write metrics JSON here")
    t.set_defaults(fn=_train)

    e = sub.add_parser("evaluate", help="evaluate a saved bundle on a labelled file")
    e.add_argument("bundle")
    e.add_argument("data")
    e.add_argument("--report", default=None)
    e.add_argument("--allow-low-match-rate", action="store_true",
                   help="evaluate on a label file whose match rate is below 50% or unknown")
    e.set_defaults(fn=_evaluate)

    args = parser.parse_args(argv)
    try:
        return args.fn(args)
    except (ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
