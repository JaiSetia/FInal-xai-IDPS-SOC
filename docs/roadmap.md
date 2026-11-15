# Roadmap: from working prototype to final project and product

Written 14 November 2026. It covers the evaluation work the project report needs (A1–A7) and the features a real deployment needs (B1–B7). The work is done **one step at a time**. Before each step, I say which model will do it, and the step starts only when you send "proceed". Nothing is committed without your yes.

## Facts the plan depends on

- **The model only knows Friday's attacks.** `friday_xgboost` was trained on PortScan, DDoS and Bot only. The lab's SSH brute force, slow DoS and web attacks are **not classes it knows**, so testing them (A1) needs a model trained on the whole CIC-IDS2017 week first (step 3).
- **Disk space is the blocker for step 3.** The Mac has **4.6 GB free**. Each day's capture is 8–13 GB, so the plan is to download one day, extract its flows (a parquet file of a few hundred MB), delete the capture, then move on to the next day. That needs about **15 GB free**, or an external drive. The labels for every day are already on disk (`data/raw/cic-ids2017/TrafficLabelling/`). After step 3, the 8.8 GB Friday capture can also be deleted if you agree, because its flows are already extracted.
- **Analysts can already mark false positives.** Alerts have a `false_positive` status, so B1 builds on data that already exists.
- **Random forest and MLP baselines exist** (`reports/friday_rf.json`, `friday_mlp.json`). A4 adds LightGBM and Suricata.
- **No git remote is set up.** Publishing images (B6) needs a GitHub repository that you create.

## Who does what

These rules come from CLAUDE.md, with your rule of no Fable:

| Work | Model |
|---|---|
| Running the lab, measurements, UI, hard bugs, write-ups | Opus 5.5 (this session) |
| Login, MFA, tokens, mTLS (B5) | Opus 5.5 at xhigh |
| Building planned features and scripts | implementer (Sonnet 5.5) |
| Tests | test-runner (Sonnet 5.5) |
| Review of Sonnet's code | reviewer (Opus 5.5) |
| Review of Opus's code | reviewer on Sonnet 5.5 |

## The steps, in order

The order puts measurements that need nothing new first, then the retrained model, which several later steps depend on. The write-up and the video come last, once every number exists. Size: S = up to an hour of work, M = a few hours, L = a day or more.

| # | Item | What gets done | Done when | Models | Needs from you | Size |
|---|---|---|---|---|---|---|
| 1 | **A5 Performance** | A benchmark script replays the Friday capture through the lab sensor at 10, 50, 100 and 200 Mbit/s. It records flows per second, dropped packets, CPU and memory, and the time from flow end to SOC alert. | `reports/perf.json` and a table in the results; the highest rate with no drops is known | implementer writes the script; Opus runs the lab | Docker Desktop running | M |
| 2 | **A2 False positives** | A normal-traffic generator for the lab: web browsing, file downloads, interactive SSH and many small requests to the victim, run for 60 minutes with no attacks. Every alert counts as a false positive. | False alerts per hour and false-positive rate per class in `reports/lab_benign.json` | implementer writes `lab/attacks/benign.sh`; Opus runs it | — | M |
| 3 | **A3a Full-week model** | Extract and label Monday to Thursday, one day at a time, then train XGBoost on all classes (brute force, DoS variants, web attacks, infiltration, PortScan, DDoS, Bot). Rerun the explanation and faithfulness reports. | `models/week_xgboost.joblib` plus reports, with per-class scores in the results | implementer adapts the pipeline; Opus runs it and checks the labels | **About 15 GB free disk** and a yes to each download | L |
| 4 | **A1 Every lab attack** | Run port scan, SSH brute force, SYN flood, slow DoS and web attacks against the victim with the new model. For each: detection rate, time to detect, whether the block worked. Run in dry-run and in blocking mode. | A per-attack table in `reports/lab_attacks.json` | Opus runs the lab | — | M |
| 5 | **A3b Unseen data** | Test the model on traffic it never trained on: our own labelled lab captures (the attacker's address gives the true label), and, if space allows, one day of CSE-CIC-IDS2018. | Scores on unseen data, set against the test-split scores, with an honest explanation of the drop | implementer writes the capture and labelling script; Opus runs and writes it up | A yes to the 2018 download (optional) | M |
| 6 | **A4 Baselines** | Add LightGBM to the trainer. Run Suricata with the free ET Open rules on the same lab captures and the Friday capture, and compare per class with the ML model. | A comparison table: ML against rules, per attack | implementer | — | M |
| 7 | **B1 Learning from analysts** | Export alerts the analysts marked (false positive or confirmed) as training rows. Add a retrain command that keeps the old model if the new one scores worse. Add model versions in the SOC (which sensor runs which model) and a drift card on the Threat Center that shows when live traffic stops looking like the training data. | Mark alerts, then retrain, then the new model version shows on the sensor; drift is shown on the dashboard | implementer builds; test-runner; Opus reviewer | — | L |
| 8 | **B2 Rules next to ML** | Run Suricata on the sensor next to the model. Its alerts go to the SOC with source "rule", and the dashboard can filter by ML or rule. Automatic blocking stays ML plus policy only, unless a rule is marked as allowed to block. | Rule alerts appear in the dashboard during a lab attack | implementer; Opus does the UI part; reviewers swap | — | L |
| 9 | **B3 Integrations** | Notifications for high and critical alerts by webhook, Slack and email, each with a test button in Admin. A syslog/CEF export for SIEMs like Splunk and Elastic. AbuseIPDB reputation on the alert page. | A lab alert arrives in Slack and in a syslog listener; the reputation shows on the alert | implementer; Opus reviewer | Optional: a Slack webhook URL, SMTP details, an AbuseIPDB key (all go in git-ignored env files) | M |
| 10 | **B4 Production database** | Support PostgreSQL alongside SQLite, add Alembic migrations (the first migration matches today's tables), configurable data retention, and a backup and restore script. | The SOC runs on Postgres in the lab; upgrade, backup and restore are tested | implementer; test-runner; Opus reviewer | — | L |
| 11 | **B5 Security** | TOTP MFA for SOC users (required for admins). Optional OIDC single sign-on. Mutual TLS between sensors and the SOC. Signed model files that the sensor checks before loading. Then a security audit of the new code. | MFA login works; a sensor without a certificate is refused; an unsigned or changed model is refused | **Opus at xhigh** builds; Sonnet reviewer; Opus audit | An outside pen test is yours to arrange (a friend or faculty member with permission) | L |
| 12 | **B6 Packaging** | Versioned Docker images, a production `docker compose` file with Caddy, a one-command install script for the SOC and the sensor, an upgrade test from the previous version, and a Helm chart (optional). | A fresh machine runs `install.sh` and reaches a working dashboard | implementer; Opus reviewer | A GitHub repository if images should be published | M |
| 13 | **B7 Reports and privacy** | A weekly PDF report (alerts, top sources, blocks, model health), downloadable and optionally emailed. Privacy controls for India's DPDP Act: retention limits, erasing an IP's data on request, a privacy notice, and an access log. | The PDF is generated from lab data; erasing an IP removes it everywhere | implementer; Opus reviewer | — | M |
| 14 | **A6 Write-up** | Rewrite `docs/results.md` with every number from steps 1–13. Add charts, architecture and data-flow diagrams, a threat model, and a limitations section covering encrypted traffic, slow-scan evasion, dataset age and Bot labels. | One document you can lift straight into the report chapters | Opus | Your report template, if the university gives one | M |
| 15 | **A7 Demo** | A demo script that resets the lab and runs a fixed attack sequence. A storyboard with what to say at each point. You record it. | A 5–7 minute recording of the live map, an alert with its explanation, a block and the Slack message | Opus writes the script and the storyboard | **You record the video** | S |

## Branches and commits

- **Merging the current work into `main` first** is recommended, so each step starts from a clean base. It needs your yes.
- **Each step gets its own commit,** made only when you approve it.
- **docs/ui-redesign.md stays as it is;** this file tracks the new work.

## Progress

| # | Status |
|---|---|
| 1 | Done, 14 Nov. Found a limit of about 1,000 flows/s in NFStream's flow expiry and fixed it with a heartbeat burst mode: peak output is now 3,200–4,500 flows/s, and flows captured at 50/200 Mbit/s rose from 29%/31% to 73%/79%. Open: capture-buffer drops aren't measured yet |
| 2 | Done, 15 Nov. 153 false alerts in 1,031 normal flows (14.8%), all low-severity PortScan on short HTTP connections, 0 would-blocks. Real lab scans all score ≥ 0.9 and false alerts never reach it, so a higher alert threshold (to be checked per class in steps 3–4) would remove them |
| 3 | Done, 15 Nov. All five days extracted and labelled (99.2–99.8% matched); `models/week_xgboost.joblib` knows 14 classes. Test macro-F1 0.662, BENIGN false-positive rate 1.14%, but 1,974 of the 2,014 false alarms are dataset label errors (the infected Thursday host's internal scan, and attacker flows outside the DDoS window), so the real rate is about 0.02%. Most attack classes have F1 above 0.9; Slowhttptest, Bot, GoldenEye and SQL injection can't be scored because of labels or the time gap |
| 4 | Done, 15 Nov. `scripts/lab_attacks.py`, `reports/lab_attacks.json`. Port scan and SSH brute force: 100% detected in the right class, blocked (SSH while it ran). SYN flood: 100% flagged and blocked, but named PortScan. Slow HTTP DoS and sqlmap: 0%, live and offline (nginx's 60 s timeout shortens slow flows; sqlmap hides in a few keep-alive connections). Blocks cut the attacker off and expire after 60 s |
| 5–15 | Not started |
