# IDPS with Explainable AI and a SOC Dashboard — Project Plan

## 1. Goal

Build a network Intrusion Detection and Prevention System that:

1. **Detects** attacks in network flows with ML models, using both a public dataset and live captured traffic.
2. **Explains** every alert with XAI (SHAP per alert, LIME for comparison), so an analyst can see *why* a flow was flagged.
3. **Prevents** attacks by blocking malicious IPs automatically through nftables, with safety rules.
4. **Supports SOC work** in a web dashboard: a live alert feed, explanations, block/unblock, incident cases and metrics.

## 2. Architecture

```
 live NIC ──┐                                    ┌──> nftables (block set, TTL)
            ├─> [capture] ─> [features] ─> [detect] ─> [respond] ──┘
 PCAP replay┘    Scapy/       flow           XGBoost +    policy engine
 (tcpreplay)     NFStream     extractor      anomaly      (allowlist, threshold)
                                               │
                                               v
                                           [explain] SHAP/LIME
                                               │
                                               v
                          [SOC API] FastAPI + PostgreSQL + WebSocket
                                               │
                                               v
                          [SOC UI]  React: alerts, explanations, blocks, cases
```

**Key design rule: use one feature extractor for training and for live traffic.**
If the model is trained on the dataset's ready-made CSV features but live traffic goes through a
different extractor, live accuracy falls apart. That's the most common way projects like this fail.
To avoid it, regenerate training features from the dataset **PCAPs** with the same extractor
(`cicflowmeter` Python port, or NFStream) that runs live, then join them to the dataset labels.

## 3. Modules

| Module | Responsibility | Main libraries |
|---|---|---|
| `idps/capture` | Sniff an interface or replay PCAPs, then group packets into flows | Scapy, NFStream / cicflowmeter, tcpreplay |
| `idps/features` | Flow → feature vector; the same code is used for training and live | pandas, numpy |
| `idps/detect` | Supervised multi-class classifier plus an unsupervised anomaly detector for unseen attacks | XGBoost, scikit-learn (RandomForest, IsolationForest) |
| `idps/explain` | Per-alert SHAP values (TreeExplainer), LIME on request, global importance reports | shap, lime |
| `idps/respond` | Policy engine: confidence threshold, allowlist (gateway, DNS, the SOC host itself), ban with a TTL, dry-run mode; writes to an nftables set with timeouts | python-nftables or subprocess `nft` |
| `soc/api` | REST + WebSocket: alerts, explanations, blocks, cases, users, metrics | FastAPI, SQLAlchemy, PostgreSQL, JWT auth |
| `soc/web` | Dashboard: live feed, alert detail with a SHAP waterfall, block/unblock, case management, KPI charts | React + Vite, TypeScript, Recharts |
| `lab/` | Isolated test network: attacker, victim and sensor | Docker Compose or VirtualBox VMs |

### Detection details
- **Datasets:** CIC-IDS2017 for training. Use the **corrected** labels (Engelen et al., 2021), because the
  original labels have known errors. Use UNSW-NB15 as a second dataset to test how well the model
  generalises to data it wasn't trained on.
- **Models:** XGBoost as the main classifier. RandomForest and a small MLP as baselines.
  IsolationForest or an autoencoder trained on benign traffic to flag zero-day attacks.
- **Class imbalance:** class weights or SMOTE on the training split only.
- **Splits:** split by time or capture day, not at random, so near-duplicate flows from the same day
  don't end up in both training and test data and inflate the scores.

### XAI details
- SHAP TreeExplainer for each alert (fast for tree models; budget under 50 ms per alert).
- LIME on demand from the dashboard, to compare it with SHAP.
- Global views: SHAP summary plot per attack class.
- **Faithfulness check** (strong material for the report): remove the top-k SHAP features and measure how much confidence drops,
  compared with removing k random features.

### Prevention safety
- A hard allowlist that can never be blocked: the gateway, DNS servers, the SOC host and the analyst IP.
- Block only when confidence ≥ threshold **and** an IP crosses N malicious flows within a time window.
- Every block has a TTL (for example 15 min) and is logged with its explanation.
- A dry-run mode that logs what *would* be blocked; use it while tuning.
- Run blocking **only inside the lab network**, never on a shared university or home network.

### SOC dashboard pages
1. Live alert feed (WebSocket), filterable by severity, class and IP.
2. Alert detail: flow fields, prediction and confidence, SHAP waterfall chart, a "Run LIME" button, and Block or Mark false positive buttons.
3. Active blocks: the list with TTLs and an Unblock button.
4. Cases: group alerts into an incident and add notes and a status (open, investigating, closed).
5. Metrics: alerts over time, attack-class breakdown, top source IPs, false-positive rate, detection latency.
6. Login with roles: analyst (triage) and admin (policy, allowlist, users).

## 4. Lab and attack scenarios

Isolated Docker or VM network: `attacker` (Kali), `victim` (Ubuntu running web and SSH services), `sensor` (the IDPS).
Run every attack only against your own lab machines.

| Scenario | Tool | Expected class |
|---|---|---|
| Port scan | nmap | PortScan |
| SSH brute force | hydra (lab creds) | Brute force |
| HTTP flood / slow DoS | hping3, slowloris | DoS |
| Web attacks | sqlmap against DVWA | Web attack |
| Dataset replay | tcpreplay of CIC-IDS2017 PCAPs | Mixed |

## 5. Repository layout

```
idps/          capture, features, detect, explain, respond (Python package)
soc/api/       FastAPI app
soc/web/       React dashboard
notebooks/     EDA and model experiments
data/          raw/ and processed/ (git-ignored)
models/        trained model files (git-ignored, with a version manifest)
lab/           docker-compose.yml, attack scripts
tests/         pytest + dashboard tests
docs/          this plan, architecture diagrams, report drafts
```

## 6. Milestones (about 14 weeks)

| Week | Milestone | Done when | Who builds it |
|---|---|---|---|
| 1 | Repo skeleton, lab network up, datasets downloaded | `docker compose up` runs all 3 lab nodes | implementer |
| 2–3 | Feature pipeline: PCAP → flows → features, labels joined | Same features come out of a PCAP and a live interface | implementer, test-runner |
| 4–5 | Models trained and evaluated (XGBoost + baselines + anomaly) | Per-class P/R/F1, confusion matrix, cross-dataset results in a notebook | implementer |
| 6 | XAI module: SHAP per alert, LIME, global plots, faithfulness test | Each alert comes with an explanation within the latency budget | implementer |
| 7 | Live detection loop on the sensor | A lab attack produces an alert within a few seconds | implementer, test-runner |
| 8 | Response engine + nftables, dry-run first | A lab attacker gets blocked and unblocked automatically; the allowlist is never blocked | implementer, then reviewer |
| 9 | SOC API: alerts, blocks, cases, WebSocket, JWT auth | API tests pass | Opus (auth at xhigh), test-runner |
| 10–11 | SOC dashboard pages 1–6 | All pages work against the live lab | Opus (UI) |
| 12 | End-to-end tests of every attack scenario, performance measurements | Results table: detection rate, FPR, latency, throughput | test-runner |
| 13 | Security review + hardening | Review findings fixed | reviewer, Fable (audit) |
| 14 | Report, demo video, slides | Ready to submit | — |

## 7. Evaluation (for the report)

- Detection: per-class precision, recall, F1, macro-F1, false-positive rate, ROC-AUC.
- Generalisation: train on CIC-IDS2017, test on UNSW-NB15 using the features they share.
- Live: detection rate per lab scenario, time-to-alert, time-to-block.
- XAI: explanation latency, a faithfulness test of SHAP versus LIME, and an optional small user study (can analysts triage faster with explanations?).
- System: flows per second the sensor can handle before it drops packets.

## 8. Risks

| Risk | Mitigation |
|---|---|
| Live features don't match the training features | One extractor for both (see §2) |
| Model scores look excellent offline but fail live | Split by time, use corrected labels, test on lab traffic |
| Auto-block locks you out | Allowlist, TTL, dry-run mode, run in the lab only |
| SHAP is too slow | TreeExplainer only for live alerts; KernelSHAP/LIME only on demand |
| Too much scope | Weeks 1–8 are the core; the dashboard can be cut back if time runs short |
