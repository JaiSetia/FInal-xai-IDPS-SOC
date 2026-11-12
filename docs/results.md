# Results — CIC-IDS2017 Friday

First run of the full pipeline on real data, 12 November 2026. The raw numbers are in `reports/friday_*.json`.

## Data

- **Capture:** `Friday-WorkingHours.pcap` (8,839,309,056 bytes), from the Hugging Face mirror
  `bencorn/CICIDS2017`. SHA-256 `beff0dcce1eebc9b2454582f4dc8ed0ba0112b2c619a710bf03af93147254cd0`,
  which matches the mirror's own checksum.
- **Labels:** the three Friday CSVs from `TrafficLabelling/` (GeneratedLabelledFlows).

```
python -m idps.features extract data/raw/pcap/Friday-WorkingHours.pcap -o data/processed/friday_flows.parquet --backend nfstream
python -m idps.features label data/processed/friday_flows.parquet <3 Friday CSVs> -o data/processed/friday_labelled.parquet --utc-offset-hours -3
python -m idps.detect train data/processed/friday_labelled.parquet --model xgboost --seed 42 -o models/friday_xgboost.joblib --report reports/friday_xgboost.json
```

- **Extraction:** 513,501 flows in 46 seconds.
- **Label time offset:** UTC−3 (the dataset's local time). It matched **99.76%** of flows, against 0.98% at −4 and 0.50% at 0.
- **Training rows:** 486,005, after dropping unmatched and ambiguous flows.

| Label | Flows |
|---|---|
| BENIGN | 289,177 |
| PortScan | 158,734 |
| DDoS | 36,866 |
| Bot | 1,228 |

## Split

- **Method:** class-time split, cut 60/20/20 by time within each class.
- **Gap:** rows starting within 120 seconds of a cut were dropped.
- **Duplicates:** exact duplicates within each split were dropped.
- **PortScan in validation:** the PortScan flows are very repetitive, so 158,734 flows reduce to a few thousand distinct ones, and the validation split has **no PortScan rows** after the gap. Validation macro-F1 (≈0.50) therefore counts PortScan as F1 = 0 because of BENIGN rows wrongly predicted as PortScan. **Use the test split** for comparing models.
- **Identical rows:** 18% of test rows are identical to some training row.

## Detection (test split)

| Model | Macro-F1 | Accuracy | BENIGN false-positive rate |
|---|---|---|---|
| XGBoost | 0.729 | 0.983 | 1.54% |
| Random forest | 0.729 | 0.983 | 1.54% |
| MLP | 0.729 | 0.982 | 1.72% |
| XGBoost without `dst_port` | 0.729 | 0.983 | 1.53% |

XGBoost per class:

| Class | Precision | Recall | F1 | Test rows |
|---|---|---|---|---|
| BENIGN | 0.996 | 0.985 | 0.990 | 35,697 |
| PortScan | 1.000 | 0.999 | 1.000 | 1,660 |
| DDoS | 0.869 | 0.995 | 0.927 | 3,646 |
| Bot | 0.000 | 0.000 | 0.000 | 123 |

- **Without `dst_port`:** dropping the port changes nothing, so the model isn't relying on port numbers.
- **Anomaly detector:** the Isolation Forest scores ROC-AUC 0.91 for attack versus normal on test. Its detection rate at the chosen threshold is near zero, so it adds nothing on this day.

## Known limitation: Bot labels

**Bot recall is 0 for every model. This is caused by the dataset's labels, not the model.**

- **The traffic:** the bot (Ares) calls its control server `205.174.165.73:8080` all day.
- **The labels:** the CSVs mark those flows **Bot from 10:04 to 12:59** and **BENIGN from 13:01 to 17:01** local time, although they come from the same infected hosts.
- **The conflict:** the bot's late check-in flow has a fixed shape: 3 packets each way, 194 and 180 bytes. It appears 490 times labelled Bot and 972 times labelled BENIGN, with identical features.
- **Why the split makes it worse:** the class-time split puts the late Bot rows in test, where the model has learnt that this exact flow shape is BENIGN.
- **AUC still high:** Bot ROC-AUC is still 0.99, so the model ranks Bot flows correctly but never predicts them.

**Decision (12 Nov 2026):** keep the published labels unchanged and report Bot as a dataset limitation. Relabelling all flows to or from the control server is a documented alternative, and it would have to be reported as a change to the dataset.

## Explanations (XGBoost)

```
python -m idps.explain faithfulness models/friday_xgboost.joblib data/processed/friday_labelled.parquet -o reports/friday_xgboost_faithfulness.json -n 100 --top-k 5
python -m idps.explain global models/friday_xgboost.joblib data/processed/friday_labelled.parquet -o reports/friday_xgboost_importance.json --plot reports/friday_xgboost_importance.png
```

**Deletion test:** 100 flows. For each flow, the top 5 features an explanation names are replaced with typical values. The bigger the drop in the model's confidence, the more faithful the explanation.

| Method | Mean confidence drop | Compared with random | Prediction changes | Beats random |
|---|---|---|---|---|
| SHAP | 0.377 | 38.6× | 42% | 100% of flows |
| LIME | 0.165 | 16.9× | 14% | 83% of flows |
| Random 5 features | 0.010 | — | — | — |

- **The median drop is small** (SHAP 0.002). The model is very confident, and many flows keep their class even with 5 features changed. The mean is driven by the 42% that change class.
- **SHAP is the better choice** for the per-alert explanations shown in the SOC.

**Global importance** (mean |SHAP|, `reports/friday_xgboost_importance.png`):

| Class | Main features | Why |
|---|---|---|
| PortScan | `bwd_bytes`, `bwd_pkt_len_max`, `rst_count` | Closed ports reply with a tiny RST |
| DDoS | `bwd_pkt_len_std`, `fwd_pkt_len_max`, `pkt_len_std` | — |
| Bot | `dst_port` (8080), `down_up_ratio` | — |
| BENIGN | `dst_port`, `syn_count`, `bwd_pkt_len_min` | — |

## Limits of these numbers

- **Single day:** all training and testing is on one day. Nothing is tested across days or datasets, so the scores show the pipeline works, not that it generalises.
- **Small Bot sample:** Bot has only 123 test rows, and their labels are unreliable (see above).
