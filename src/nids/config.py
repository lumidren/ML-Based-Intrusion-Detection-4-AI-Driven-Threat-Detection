"""Central configuration (environment-driven, 12-factor) and fixed constants."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

SEED = 20170703
"""Global random seed: the first capture day of CIC-IDS2017 (3 July 2017)."""


class Settings(BaseSettings):
    """Runtime settings. Every field can be overridden by an ``NIDS_`` environment variable."""

    model_config = SettingsConfigDict(env_prefix="NIDS_", env_file=".env", extra="ignore")

    data_root: Path = Field(default=Path("data"), description="Root for raw/interim/processed data")
    artifacts_root: Path = Field(default=Path("artifacts"), description="Model & report artifacts")
    mlflow_tracking_uri: str = Field(default="file:./mlruns")
    mlflow_experiment: str = Field(default="nids")

    kafka_bootstrap: str = Field(default="localhost:9092")
    kafka_flows_topic: str = Field(default="nids.flows")
    kafka_alerts_topic: str = Field(default="nids.alerts")
    kafka_group_id: str = Field(default="nids-inference")

    postgres_dsn: str = Field(default="postgresql://nids:nids@localhost:5432/nids")
    redis_url: str = Field(default="redis://localhost:6379/0")

    sensor_id: str = Field(default="sensor-local")
    sensor_hmac_key: str = Field(default="change-me-in-production", min_length=8)
    flow_timeout_s: float = Field(default=120.0, description="CICFlowMeter default flow timeout")
    activity_timeout_s: float = Field(
        default=5.0, description="CICFlowMeter default activity timeout"
    )

    alert_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    target_fpr: float = Field(default=0.001, gt=0.0, lt=1.0)
    max_batch: int = Field(default=1024, ge=1)

    mem_limit_mb: int = Field(
        default=2500, ge=256, description="Stop a job when its RSS exceeds this (MB)"
    )
    min_free_mb: int = Field(
        default=1000, ge=0, description="Stop a large job when system free RAM drops below this"
    )
    threads: int = Field(default=4, ge=1, description="Native thread-pool size for heavy jobs")

    log_json: bool = Field(default=True)
    otel_endpoint: str | None = Field(
        default=None, description="OTLP gRPC endpoint; None disables export"
    )

    @property
    def raw_dir(self) -> Path:
        return self.data_root / "raw"

    @property
    def interim_dir(self) -> Path:
        return self.data_root / "interim"

    @property
    def processed_dir(self) -> Path:
        return self.data_root / "processed"

    @property
    def pcap_dir(self) -> Path:
        return self.data_root / "pcaps"


def get_settings() -> Settings:
    """Return a fresh Settings instance (cheap; reads env each call so tests can override)."""
    return Settings()
