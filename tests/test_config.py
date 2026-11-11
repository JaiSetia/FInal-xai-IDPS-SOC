from idps.config import Settings


def test_defaults():
    s = Settings()
    assert s.dry_run is True
    assert s.block_ttl_seconds == 900
    assert s.confidence_threshold == 0.9
    assert s.allowlist == []
