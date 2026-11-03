"""``nids`` command-line interface (typer)."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from nids.config import get_settings
from nids.logging import configure_logging

app = typer.Typer(help="ML-based network intrusion detection toolkit", no_args_is_help=True)
data_app = typer.Typer(help="Dataset download, canonicalisation, validation and profiling")
app.add_typer(data_app, name="data")
console = Console()


@app.callback()
def _root(json_logs: bool = typer.Option(True, help="Emit JSON logs")) -> None:
    configure_logging(json_output=json_logs)


@data_app.command("canonicalise")
def data_canonicalise(
    dataset: str | None = typer.Option(None, help="cicids2017 | cseids2018 | all"),
) -> None:
    """Convert raw CSVs to canonical parquet."""
    from nids.data.loaders import canonicalise_all
    from nids.data.schema import Dataset

    s = get_settings()
    ds = None if dataset in (None, "all") else (Dataset(dataset),)
    written = canonicalise_all(s.raw_dir, s.processed_dir, ds)
    for p in written:
        console.print(f"wrote {p}")
    if not written:
        raise typer.Exit(code=1)


@data_app.command("validate")
def data_validate(
    strict: bool = typer.Option(False, help="Disallow inf/null (post-cleaning)"),
) -> None:
    """Validate canonical parquet files and write a JSON report."""
    from nids.data.loaders import load_canonical
    from nids.data.validation import validate_canonical, write_ge_suite

    s = get_settings()
    df = load_canonical(s.processed_dir)
    rep = validate_canonical(df, allow_inf=not strict)
    out = s.artifacts_root / "reports" / "validation.json"
    rep.write(out)
    write_ge_suite(s.artifacts_root / "reports" / "great_expectations_suite.json")
    console.print_json(json.dumps(rep.as_dict(), default=str))
    if not rep.passed:
        raise typer.Exit(code=1)


@data_app.command("profile")
def data_profile(card: Path = typer.Option(Path("docs/DATA_CARD.md"))) -> None:
    """Compute measured statistics and update the data card."""
    from nids.data.loaders import load_canonical
    from nids.data.profile import profile, update_data_card

    s = get_settings()
    p = profile(load_canonical(s.processed_dir))
    update_data_card(card, p, s.artifacts_root / "reports" / "data_profile.json")
    console.print(f"updated {card}")


@data_app.command("split")
def data_split(
    holdout_days: str = typer.Option("", help="comma-separated day ids to hold out"),
    holdout_datasets: str = typer.Option("", help="comma-separated dataset ids to hold out"),
) -> None:
    """Clean, split (temporal, group-aware) and write data/processed/splits/*.parquet."""
    from nids.data.cleaning import clean
    from nids.data.loaders import load_canonical
    from nids.data.splits import SplitConfig, assert_no_leakage, fold_summary, temporal_split

    s = get_settings()
    df = load_canonical(s.processed_dir)
    cleaned, rep = clean(df)
    cfg = SplitConfig(
        holdout_days=tuple(x for x in holdout_days.split(",") if x),
        holdout_datasets=tuple(x for x in holdout_datasets.split(",") if x),
    )
    split = temporal_split(cleaned, cfg)
    assert_no_leakage(split)
    out = s.processed_dir / "splits"
    out.mkdir(parents=True, exist_ok=True)
    for (fold,), sub in split.group_by("fold"):
        sub.write_parquet(out / f"{fold}.parquet", compression="zstd")
    (out / "cleaning_report.json").write_text(json.dumps(rep.as_dict(), indent=2))
    console.print(fold_summary(split))


if __name__ == "__main__":
    app()
