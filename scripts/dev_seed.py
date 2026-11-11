"""Fill a DEVELOPMENT SOC database with demo users, a sensor and sample alerts.

    IDPS_SOC_JWT_SECRET=... IDPS_SOC_DATABASE_URL=sqlite:///./dev-soc.db \
        python scripts/dev_seed.py --i-understand-this-adds-demo-logins

Demo logins (development only; never use these on a real deployment):
    admin   / demo-admin-password
    analyst / demo-analyst-password

The sample alerts go through the real ingest endpoint, so they are validated like a sensor's.
Safety: it only runs with the explicit flag above, only against a SQLite database that was
named on purpose (IDPS_SOC_DATABASE_URL set, and not the API's default ./soc.db), so the
known demo passwords can't end up in a real SOC database by accident.
"""

import random
import sys

from fastapi.testclient import TestClient

from soc.api import auth
from soc.api.main import create_app
from soc.api.models import Role, User
from soc.api.settings import get_settings

DEMO_USERS = {"admin": ("demo-admin-password", Role.ADMIN),
              "analyst": ("demo-analyst-password", Role.ANALYST)}

# (class, dst_port, top features) for plausible-looking sample explanations
SAMPLES = [
    ("PortScan", 22, ["syn_count", "fwd_packets", "duration_ms", "rst_count", "bwd_bytes"]),
    ("DDoS", 80, ["packets_per_s", "fwd_iat_mean", "fwd_packets", "pkt_len_mean", "syn_count"]),
    ("SSH-Patator", 22, ["dst_port", "fwd_bytes", "psh_count", "iat_mean", "bwd_pkt_len_max"]),
    ("Bot", 8080, ["dst_port", "bwd_bytes", "fwd_iat_std", "duration_ms", "ack_count"]),
    ("DoS Hulk", 80, ["bwd_pkt_len_max", "fwd_packets", "psh_count", "iat_max", "bytes_per_s"]),
]


FLAG = "--i-understand-this-adds-demo-logins"


def main() -> int:
    import os

    if FLAG not in sys.argv[1:]:
        print(f"refusing: this adds well-known demo passwords; pass {FLAG} to confirm",
              file=sys.stderr)
        return 1
    url = os.environ.get("IDPS_SOC_DATABASE_URL", "")
    default_url = type(get_settings()).model_fields["database_url"].default
    if not url or url == default_url or not url.startswith("sqlite"):
        print("refusing: set IDPS_SOC_DATABASE_URL to a separate SQLite development database "
              f"(not {default_url!r})", file=sys.stderr)
        return 1
    settings = get_settings()
    app = create_app(settings)
    rng = random.Random(7)
    with app.state.session_factory() as db:
        for name, (password, role) in DEMO_USERS.items():
            if db.query(User).filter_by(username=name).first() is None:
                auth.create_user(db, name, password, role)
        token = auth.create_sensor_token(db, f"demo-sensor-{rng.randrange(10**6)}")

    client = TestClient(app)
    now_ms = int(__import__("time").time() * 1000)
    alerts = []
    for i in range(40):
        cls, port, feats = rng.choice(SAMPLES)
        conf = round(rng.uniform(0.55, 0.995), 3)
        start = now_ms - rng.randrange(0, 6 * 3600 * 1000)
        contribs = sorted((round(rng.uniform(-0.4, 1.6), 3) for _ in feats), key=abs, reverse=True)
        alerts.append({
            "src_ip": f"10.10.1.{rng.choice([10, 10, 10, 23, 47])}", "src_port": rng.randrange(1024, 65535),
            "dst_ip": f"10.10.2.{rng.choice([10, 11])}", "dst_port": port, "protocol": 6,
            "start_ms": start, "end_ms": start + rng.randrange(5, 120_000),
            "predicted_class": cls, "confidence": conf, "anomaly_score": round(rng.uniform(0, 1), 3),
            "explanation": {"method": "shap", "predicted_class": cls, "confidence": conf,
                            "base_value": -1.2, "output_space": "log_odds",
                            "top_features": [{"feature": f, "value": round(rng.uniform(0, 500), 2),
                                              "contribution": c} for f, c in zip(feats, contribs)]},
        })
    r = client.post("/ingest/alerts", json={"alerts": alerts},
                    headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    print(f"seeded {r.json()['accepted']} alerts; demo users: {', '.join(DEMO_USERS)}")
    print("sensor token for sending more alerts (dev only):", token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
