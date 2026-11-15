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

## Sensor performance (lab, 14 November 2026)

**What was run:** `python3 scripts/bench_sensor.py`. A 226 MB sample of the Friday capture (1,301,052 packets, PortScan and DDoS windows) was replayed through the lab sensor at four rates. The offline extraction of the same sample gives **191,362 flows**. The Docker VM has 8 CPUs and 4 GB of memory, and the sensor runs in dry-run mode.

The first run found a limit of about 1,000 flows/s. After fixing it (below), the benchmark was run again. The before numbers are in `reports/perf_before_burst.json`, the after numbers in `reports/perf.json`. A run with a batch of 1,024 flows is in `reports/perf_batch1024.json`.

| Target Mbit/s (actual after) | Flows captured, before → after | Peak flows/s, before → after | Burst drain time*, before → after | CPU during drain | Peak memory |
|---|---|---|---|---|---|
| 10 (10.0) | 93% → 90% | 1,055 → 3,205 | (still draining at 400 s) → ~60 s | 54% | 927 MiB |
| 50 (50.0) | 29% → **73%** | 1,017 → 4,505 | 70 s → 70 s | 39% | 830 MiB |
| 100 (100.0) | 58% → **64%** | 1,037 → 3,943 | 120 s → **50 s** | 33% | 774 MiB |
| 200 (126.9, the replay tool's maximum) | 31% → **79%** | 1,011 → 4,516 | 60 s → 70 s | 39% | 875 MiB |

\*From the first flow coming out of the capture to the last, read from `flows_timeline`, which samples every 10 s. After the fix, the same or shorter drain times hold up to 2.5× more flows.

- **Alerts:** none were dropped or rejected by the SOC, and no errors occurred.
- **SHAP time:** p95 stayed at 0.23–0.29 ms per alert.
- **Interfaces:** the capture interface showed 0 `rx_dropped`, 0 errors and 0 softnet drops.

### The limit and the fix

**The model wasn't the limit.**
- A run at 100 Mbit/s with a scoring batch of 1,024 flows instead of 64 gave the same rate (1,104 flows/s peak).
- The limit is NFStream 6.6.0. It expires idle flows only when a packet arrives, and expires at most 1,000 per scan (`nfstream/meter.py`, `meter_scan`).
- After a burst, the only packet left was the sensor's 1 s heartbeat. So finished flows came out at about 1,000 a second, and a 100,000-flow burst took minutes to reach the SOC.

**The fix: a burst mode for the heartbeat** (`idps/live/heartbeat.py`).
- **When it starts:** when at least 900 flows come out in one second, which means the output is capped. The heartbeat then sends every 50 ms.
- **When it stops:** once fewer than 250 flows a second have come out for 3 s, it goes back to once a second.
- **Cost:** 20 one-byte broadcasts a second, and only while a backlog drains.
- **Off switch:** `--heartbeat-burst-interval 0` turns it off.

After the fix, peak output is 3,200–4,500 flows/s, and the model's scoring speed is now the limit.

### What these numbers don't show

- **Alert delay (not in the table).** The sensor's latency figure covers only its last 2,000 alerts (its metrics window). In runs with 70,000–120,000 alerts that is the end of the drain, so it isn't a fair typical figure. Every alert waits at least the 120 s idle timeout. The drain time above is how much longer the slowest alert of a burst waits.
- **Packet loss inside the capture.** The interface counters don't include the capture library's own ring buffer, and that buffer's drop counter isn't read yet. So "no packets dropped" can't be claimed.
- **Why captured flows stay under 100%.** Two possible causes are not yet separated:
  - **Time compression:** replay squeezes 20 minutes of traffic into 10–165 s, so connections that were separate in the original capture fall within one 120 s idle timeout and are counted as one flow.
  - **Real losses:** flows may be lost in that ring buffer.
- **Next step for this:** read NFStream's drop statistics, and count offline flows with the replay's own timing.

## False positives on normal traffic (lab, 15 November 2026)

**What was run:** `python3 scripts/bench_benign.py --minutes 60`. One busy user's normal activity went from the lab client (10.10.1.10) to the victim (nginx, sshd) and DVWA, through the dry-run sensor with the Friday XGBoost model. The mix was:
- page views fetched like a browser does, with keep-alive and up to 6 parallel connections
- DVWA logins
- downloads of 100 KB to 50 MB
- SSH sessions and scp copies
- request bursts and pings
- a small share of one-connection-per-request traffic, the way scripts and health checks behave

Neither the client nor the victims were allowlisted. Only normal traffic ran, so **every alert is a false positive**. Each alert was matched to the activity that caused it by its client port. The raw data is in `reports/lab_benign.json`.

| Measure | Result |
|---|---|
| Traffic | 60.3 min, 1,031 flows scored |
| False alerts | **153**: 152 per hour, **14.8% of flows** |
| Class and severity | all PortScan, all low severity |
| Would-blocks | **0**: no alert was confident enough for the blocking policy |
| Run checks | valid: the sensor and SOC counts agree (153 = 153), no alerts were waiting from earlier runs, nothing was excluded or duplicated |

| Activity | Connections | False alerts | Rate per connection |
|---|---|---|---|
| Web page views (nginx) | 303 | 90 | 29.7% |
| DVWA pages and logins | 274 | 45 | 16.4% |
| One connection per request | 122 | 17 | 13.9% |
| Request bursts (keep-alive) | 156 | 1 | 0.6% |
| Downloads | 27 | 0 | 0 |
| SSH sessions | 48 | 0 | 0 |
| scp | 72 | 0 | 0 |
| Ping | 20 | 0 | 0 |

**All false alerts are short HTTP connections on port 80.**
- **The traffic:** connections that carry one or two small requests and close. Browsers make these when they open several connections in parallel for a page's assets.
- **The model's view:** it learnt PortScan from Friday's data, where a scan probe is a short TCP exchange with a tiny reply (`bwd_bytes`, `bwd_pkt_len_max`, see the explanations above). A short HTTP connection looks similar.
- **What it never confused:** long transfers, SSH and keep-alive bursts.
- **Lab caveat:** the lab's round-trip time is about 0.1 ms. On a real network, timing features would differ, so the rate there may be higher or lower.

### Confidence separates false alerts from real scans

| | Alerts | Median confidence | Confidence ≥ 0.8 | Confidence ≥ 0.9 |
|---|---|---|---|---|
| False alerts (this run) | 153 | 0.60 | 3 (2%) | 0 |
| Real lab port scans (14 Nov runs, 10.10.1.10 → victim) | 5,122 | 0.99999 | 5,122 (100%) | 5,122 (100%) |

- **The finding:** raising the alert threshold from 0.5 to 0.9 would have removed **all 153 false alerts**, and every real lab port-scan alert would still have fired.
- **At 0.8:** 3 false alerts an hour would remain.
- **Why the default is unchanged:**
  - Only one attack type (nmap port scans) was checked this way.
  - The model is still the Friday-only model.
  - The threshold must be checked again for each attack class after the full-week model (roadmap step 3) and the lab attack tests (step 4).
- **Recommendation:** pick a threshold per class from those runs.

**Possible bias:** the "normal" client is the same container the attack scripts run from. The model keeps no state between flows, so earlier attacks don't affect these scores.

## Full-week model (CIC-IDS2017 Monday–Friday, 15 November 2026)

```
python -m idps.detect train data/processed/{monday,tuesday,wednesday,thursday,friday}_labelled.parquet --model xgboost -o models/week_xgboost.joblib --report reports/week_xgboost.json
python -m idps.detect train (same files) --model xgboost --drop-feature dst_port -o models/week_xgboost_noport.joblib --report reports/week_xgboost_noport.json
```

**Data:** each day's capture was downloaded (SHA-256 checked against the Hugging Face mirror), extracted with NFStream, labelled with `--utc-offset-hours -3` and then deleted.

| Day | Flows | Labelled | Attack flows |
|---|---|---|---|
| Monday | 372,070 | 99.7% | none (normal day) |
| Tuesday | 321,856 | 99.2% | SSH-Patator 2,922, FTP-Patator 2,468 |
| Wednesday | 422,751 | 99.8% | DoS Hulk 77,934, GoldenEye 7,565, slowloris 5,355, Slowhttptest 4,502, Heartbleed 9 |
| Thursday | 355,130 | 99.3% | Web brute force 143, Infiltration 34, XSS 21, SQL injection 9 |
| Friday | 513,501 | 99.8% | PortScan, DDoS, Bot |

The training set is 1,942,434 rows, split by class and time (60/20/20, with a 120 s gap). Training takes about 2 minutes. The model's SHA-256 starts `4a59a3564377`.

| Model | Macro-F1 | Accuracy | BENIGN false-positive rate |
|---|---|---|---|
| Week XGBoost | 0.662 | 0.984 | 1.14% |
| Week XGBoost without `dst_port` | 0.616 | 0.983 | 1.17% |
| Friday XGBoost (for comparison, Friday only) | 0.729 | 0.983 | 1.54% |

Week XGBoost per class (test split):

| Class | Precision | Recall | F1 | Test rows |
|---|---|---|---|---|
| BENIGN | 0.995 | 0.989 | 0.992 | 177,097 |
| DoS Hulk | 1.000 | 0.925 | 0.961 | 10,701 |
| DDoS | 0.855 | 0.995 | 0.920 | 3,646 |
| PortScan | 0.544 | 0.999 | 0.704 | 1,660 |
| SSH-Patator | 1.000 | 0.979 | 0.990 | 485 |
| FTP-Patator | 0.959 | 1.000 | 0.979 | 398 |
| DoS slowloris | 1.000 | 0.731 | 0.845 | 275 |
| DoS Slowhttptest | 0.000 | 0.000 | 0.000 | 127 |
| Bot | 0.000 | 0.000 | 0.000 | 123 |
| Web Attack - Brute Force | 0.913 | 1.000 | 0.955 | 21 |
| Infiltration | 0.857 | 1.000 | 0.923 | 6 |
| Web Attack - XSS | 0.000 | 0.000 | 0.000 | 3 |
| Heartbleed | 1.000 | 1.000 | 1.000 | 1 |
| DoS GoldenEye | — | — | 0.000 | 0 |

### Most false alarms are label errors in the dataset

Of the 2,014 BENIGN test flows flagged as attacks:

- **1,360 (PortScan)** all come from **192.168.10.8 between 15:39 and 15:45 on Thursday**, to internal hosts on many ports. That is the infected machine scanning the internal network after the infiltration. The dataset labels it BENIGN; the model calls it a port scan, which it is.
- **614 (DDoS)** are flows between the **attacker's address 172.16.0.1 and the Friday web server 192.168.10.50 on port 80** that fall outside the labelled DDoS window.
- **40 remain**, about **0.02%** of normal test flows. That is the real false-positive rate on this data.

So the PortScan precision of 0.544 and much of the 1.14% understate the model. The labels were kept as published (the same decision as for Bot), and the correction is reported here.

### Why some classes score 0, and why macro-F1 is lower than Friday's

- **Slowhttptest:** its test rows have a median duration of 1 ms and go to high ports (median 38098). Its train rows last about 105 s and go to port 80. The test rows are reply-like flows inside the labelled window, not the attack itself, so this is a labelling artefact.
- **Bot:** the same label conflict as on Friday (see above).
- **GoldenEye and SQL injection:** the attacks are short bursts, and the 120 s gap removed all their test rows (GoldenEye loses 5,519 rows, SQL injection all 9). GoldenEye still counts as F1 0 in the macro average because the model predicts it 239 times, mostly for DoS Hulk.
- **XSS (3 rows) and Heartbleed (1 row)** are too small to score.

Macro-F1 averages over all of these equally, so it falls even though most attack classes score above 0.9.

### Confidence threshold

Raising the alert threshold barely lowers false alarms here (1.13% at 0.5, 1.10% at 0.9), because the label-error flows above are predicted with confidence about 1. It costs attack recall (93% at 0.5, 85% at 0.9, 68% at 0.99). On real normal lab traffic (see the false-positive section), a higher threshold still helps; this is checked per class in the lab test of every attack.

### Without `dst_port`

Macro-F1 drops from 0.662 to 0.616. Most of the drop is Infiltration (F1 0.92 to 0.29). The other classes change by 0.01–0.03, so the model mostly isn't relying on port numbers.

### Explanations

The flows tested are a stratified test-split sample: up to 40 per class, plus 200 normal flows, 551 in all (`data/processed/week_explain_sample.parquet`).

| Method | Mean confidence drop | Compared with random | Prediction changes | Beats random |
|---|---|---|---|---|
| SHAP | 0.416 | 7.8× | 42% | 87% of flows |
| LIME | 0.239 | 4.5× | 25% | 64% of flows |
| Random 5 features | 0.053 | — | — | — |

SHAP is still the more faithful method. The ratio is lower than on Friday because removing random features also moves this model's confidence more (0.053 against 0.010).

Global importance (top 3 by mean |SHAP|, `reports/week_xgboost_importance.png`):

| Class | Main features |
|---|---|
| PortScan | `rst_count`, `fwd_bytes`, `fwd_iat_std` |
| DoS Hulk | `rst_count`, `pkt_len_std`, `bwd_iat_max` |
| DoS slowloris | `bwd_iat_mean`, `pkt_len_max`, `bwd_bytes` |
| DDoS | `down_up_ratio`, `fwd_pkt_len_max`, `fwd_pkt_len_mean` |
| SSH-Patator | `dst_port`, `fwd_pkt_len_max`, `packets_per_s` |
| FTP-Patator | `dst_port`, `packets_per_s`, `iat_mean` |
| Web brute force | `fwd_pkt_len_std`, `duration_ms`, `pkt_len_max` |
| Infiltration | `dst_port`, `bwd_pkt_len_min`, `fin_count` |

The slow DoS class is explained by gaps between packets, and port scans by reset packets. Both match how these attacks work.

## Every lab attack with the full-week model (lab, 15 November 2026)

```
python scripts/lab_attacks.py      # writes reports/lab_attacks.json
```

**Method:**

1. Each attack script runs from the attacker container against the lab victim, once in dry-run and once with real blocking. Both modes use a 60 s block time.
2. The sensor runs `models/week_xgboost.joblib` and sends its alerts to the lab SOC.
3. tcpdump on the sensor records every packet to and from the attacker. The recording is the ground truth: it gives the attacker's flows, and the same model scores them offline.
4. **Detection rate** = the attacker's flows alerted as the right attack family, divided by all the attacker's flows.

| Attack | Attacker flows | Flagged as an attack | Right family | Class given | Median confidence | First alert | Dry-run: would block | Blocking: blocked at | Attacker's HTTP before → during → after the block |
|---|---|---|---|---|---|---|---|---|---|
| Port scan (nmap SYN, ports 1–1024) | 1,024 | 100% | 100% | PortScan | 0.995 | 122 s | yes | 123 s | 200 → none → 200 |
| SSH brute force (hydra, 210 passwords) | 45 | 100% | 100% | SSH-Patator | 0.992 | 126 s | yes | 175 s, during the attack | 200 → none → 200 |
| SYN flood (hping3, 2,000/s for 20 s) | 26,606 | 100% | 0% | PortScan | 0.996 | 122 s | yes | 123 s | 200 → none → 200 |
| Slow HTTP DoS (slowhttptest, 500 connections) | 523 | 0% | 0% | — | — | — | no | no block | — |
| SQL injection (sqlmap against DVWA) | 9 | 0% | 0% | — | — | — | no | no block | — |

The flow counts are from the dry-run; the blocking runs match within a few flows. The offline score of each recording equals the live result, so no flows were lost by the live capture and every result comes from the model itself.

### What this shows

- **Port scan and SSH brute force are detected, alerted and blocked.**
  - The first alert comes about 2 minutes after the first packet. That is NFStream's 120 s idle timeout: a flow is only scored once it has ended.
  - The port scan is over in half a second, so its block comes after the scan. The block still works: during it the attacker gets no answer from the victim, and access returns by itself after 60 s.
  - The SSH brute force runs for minutes. It was **blocked while it was still running** (at 175 s), which cut the rest of the attack off. Hydra took 428 s instead of 191 s, and 7 of its later flows were connection attempts that never got through (scored BENIGN, as they carry no data).
- **The SYN flood is caught and blocked, but named PortScan.** Each spoofed-port SYN is its own flow: one SYN, the victim's SYN-ACK and a reset. That is exactly what one probe of a SYN port scan looks like, so the flow features can't tell the two apart. CIC-IDS2017's DoS classes come from HTTP floods (Hulk, GoldenEye), not SYN floods, so the model has never seen this attack. The response is right (block the source); the label is wrong.
- **Slow HTTP DoS is missed.** All 523 flows score BENIGN, live and offline.
  - The lab's nginx closes a connection that hasn't finished its headers after 60 s (the default `client_header_timeout`), so the attack's flows last about a minute.
  - The model learnt slowloris from CIC-IDS2017's Apache server, whose flows lasted 75–105 s.
  - A different server with a different timeout changes the features enough to hide the attack. This is a limit of training on one dataset, examined in the next step (unseen data).
- **SQL injection is missed, and flow features can't catch it.**
  - sqlmap sent about 77 requests per run, all reaching DVWA. But it reuses each connection for many requests, so the whole attack is a handful of flows that look like ordinary web browsing.
  - The attack is in the request text (`' AND 1506=(SELECT ...`), which a flow model never sees.
  - This needs payload inspection: the rule-based Suricata comparison in the next steps.
  - The first sqlmap run had replayed results cached from an earlier run, and only the rerun with `--flush-session` is reported.

### Summary for the report

Of five lab attacks, **three are detected and blocked** (port scan, SSH brute force, SYN flood) and **two are missed** (slow HTTP DoS, SQL injection). None of the attacks produced a false block of a protected server, and every block ended by itself after its 60 s. The misses come from the limits of flow features and of a single training dataset, not from the sensor: the offline score of each recording matches the live result exactly. These are the cases where adding rules next to the model is worth it.

## Unseen data: our own labelled lab traffic (lab, 15 November 2026)

The full-week model was scored on traffic it never trained on: two rounds of every lab attack plus 2 × 10 minutes of normal traffic (web browsing, downloads, SSH and SCP sessions, ping), recorded on the sensor with tcpdump and turned into flows with the same NFStream features as the live sensor. The true label comes from the recording itself: in an attack recording, every flow to or from the attacker (10.10.1.10) is that attack, and in a normal-traffic recording every flow is BENIGN. DVWA's setup and login requests before sqlmap starts are left out. Script: `scripts/lab_unseen.py`; data: `data/processed/lab_labelled.parquet` (git-ignored); report: `reports/lab_unseen.json` (model checksum 4a59a3564377…).

The test split was scored without the 0.5 alert floor, so the comparison below uses the lab scores without it too. The floor changed nothing here.

| Class | Lab flows | Lab recall | Test-split recall | Test-split F1 |
|---|---|---|---|---|
| BENIGN | 386 | 91.7% | 98.9% | 0.992 |
| PortScan | 2,048 | 100% | 99.9% | 0.704 |
| SSH-Patator | 90 | 98.9% | 97.9% | 0.990 |
| DoS slowloris | 1,046 | **0%** | 73.1% | 0.845 |
| SYN flood (not a model class) | 53,742 | 0% as DoS (100% as PortScan) | — | — |
| SQL injection (not a model class) | 8 | 0% (all BENIGN) | — | — |

Recall is the fair column. F1 and precision depend on how many normal flows there are per attack flow, and the lab has far fewer normal flows than the test split.

### What this shows

- **Attacks that look the same everywhere carry over.** Port scan and SSH brute force score as well on our own network as on the test split, even though the hosts, addresses, operating systems and tools (nmap, hydra) are all different.
- **Normal web traffic is now clean.** All 353 normal web flows score BENIGN. With the Friday-only model, 14.8% of normal lab flows were false PortScan alerts (step 2), so training on the whole week fixed that.
- **Every normal SSH session is flagged as SSH brute force** (28 of 28, median confidence 0.89, up to 0.99). Most of the generator's SSH flows are SCP copies of a small file (median 0.2 s), plus a few interactive sessions of up to 32 s. Each one is a password login followed by a short exchange, which looks like one brute-force attempt. CIC-IDS2017 has very little normal SSH, so the model learnt "short SSH session means attack". The remaining false positives are 4 ping flows called FTP-Patator, at low confidence (0.52–0.81). So the lab false-positive rate, 8.3% (32 of 386), is much higher than the test split's 1.1%. No block is likely: blocking needs 5 confident flows from one source within 60 s, and the normal traffic makes about 1–2 SSH logins a minute. But an analyst would see these alerts.
- **Slow HTTP DoS doesn't carry over at all.** The lab's nginx cuts the slow connections at 60 s (median flow 60.0 s), while the CIC-IDS2017 Apache flows the model learnt from lasted 75–105 s. A change of web server is enough to hide the attack.
- **Attacks the dataset doesn't have are missed or misnamed.** The SYN flood is called PortScan (each flood packet looks like one scan probe), and SQL injection looks like browsing.

### Summary for the report

On unseen traffic the model keeps its scores for attacks whose flows look the same on any network (scans and brute force) and loses them where the training data was narrow: one web server's timeout (slowloris), too little normal SSH (false SSH-Patator alerts), and attack types the dataset never had (SYN flood, SQL injection). This is the dataset-generalisation gap reported in the literature on CIC-IDS2017, measured on our own network. The fixes are more varied training data (B1's analyst feedback, or a second dataset like CSE-CIC-IDS2018) and rules next to the model for what flows can't show (B2).

Limitations: 386 normal flows is a small sample, and the normal traffic comes from one generator on one host. CSE-CIC-IDS2018 was not tested (optional, needs a download).
