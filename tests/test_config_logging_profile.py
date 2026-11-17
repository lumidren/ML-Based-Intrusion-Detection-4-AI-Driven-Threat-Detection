"""Tests for config, logging and the data-card profile generator."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
import structlog

from nids.config import SEED, Settings, get_settings
from nids.data.profile import BEGIN, END, profile, to_markdown, update_data_card
from nids.logging import configure_logging, get_logger
from tests.conftest import make_canonical


def test_settings_defaults_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    s = Settings()
    assert s.raw_dir == Path("data") / "raw"
    assert s.processed_dir.name == "processed"
    assert s.interim_dir.name == "interim"
    assert s.pcap_dir.name == "pcaps"
    assert SEED == 20170703
    monkeypatch.setenv("NIDS_DATA_ROOT", "/tmp/elsewhere")
    monkeypatch.setenv("NIDS_MAX_BATCH", "7")
    s2 = get_settings()
    assert s2.data_root == Path("/tmp/elsewhere")
    assert s2.max_batch == 7


def test_settings_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NIDS_TARGET_FPR", "2")
    with pytest.raises(ValueError):
        get_settings()


def test_logging_json_and_console(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(json_output=True, level=logging.INFO)
    log = get_logger("t")
    log.info("hello", k=1)
    err = capsys.readouterr().err
    rec = json.loads(err.strip().splitlines()[-1])
    assert rec["event"] == "hello" and rec["k"] == 1 and rec["level"] == "info"
    configure_logging(json_output=False)
    get_logger("t").warning("plain")
    assert "plain" in capsys.readouterr().err
    structlog.reset_defaults()


def test_logging_adds_trace_context_when_span_active(capsys: pytest.CaptureFixture[str]) -> None:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider

    trace.set_tracer_provider(TracerProvider())
    configure_logging(json_output=True)
    tracer = trace.get_tracer("t")
    with tracer.start_as_current_span("s"):
        get_logger("t").info("in-span")
    rec = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
    assert len(rec["trace_id"]) == 32 and len(rec["span_id"]) == 16
    structlog.reset_defaults()


def test_profile_and_data_card_update(tmp_path: Path) -> None:
    df = make_canonical(n=500, days=("2017-07-04-tue", "d2"))
    p = profile(df)
    assert p["rows"] == 1000
    ds = p["datasets"]["cicids2017"]
    assert ds["rows"] == 1000
    assert 0 < ds["attack_frac"] < 1
    days = {d["day"]: d for d in ds["days"]}
    assert days["2017-07-04-tue"]["expected_rows"] == 445_909
    assert days["d2"]["expected_rows"] is None
    # attack rows all hit port 22, benign all 443 => port 22 is 100% attack
    assert ds["top_attack_ports"][0]["port"] == 22
    assert ds["top_attack_ports"][0]["attack_share"] == 1.0
    assert "| 22 |" in to_markdown(p)
    md = to_markdown(p)
    assert "| 2017-07-04-tue |" in md and "445,909" in md
    card = tmp_path / "DATA_CARD.md"
    card.write_text(f"# Card\n\n{BEGIN}\nold\n{END}\n", encoding="utf-8")
    update_data_card(card, p, tmp_path / "r" / "profile.json")
    text = card.read_text(encoding="utf-8")
    assert "old" not in text and "Total canonical rows" in text
    assert (tmp_path / "r" / "profile.json").exists()
