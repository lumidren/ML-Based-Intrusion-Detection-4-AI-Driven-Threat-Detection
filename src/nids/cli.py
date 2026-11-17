"""``nids`` command-line interface (typer)."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from nids import resources
from nids.config import get_settings
from nids.logging import configure_logging, get_logger

app = typer.Typer(help="ML-based network intrusion detection toolkit", no_args_is_help=True)
data_app = typer.Typer(help="Dataset download, canonicalisation, validation and profiling")
app.add_typer(data_app, name="data")
console = Console()
_log = get_logger("nids.cli")


@app.callback()
def _root(
    ctx: typer.Context,
    json_logs: bool = typer.Option(True, help="Emit JSON logs"),
    mem_limit_mb: int | None = typer.Option(
        None, help="Stop the job above this RSS (default NIDS_MEM_LIMIT_MB or 2500)"
    ),
) -> None:
    """Every command runs with capped threads, below-normal priority and a memory watchdog."""
    configure_logging(json_output=json_logs)
    s = get_settings()
    resources.cap_threads(s.threads)
    resources.lower_priority()
    dog = resources.MemoryWatchdog(mem_limit_mb or s.mem_limit_mb, s.min_free_mb).start()
    ctx.call_on_close(lambda: _log.info("resources", peak_rss_mb=round(dog.stop())))


@data_app.command("canonicalise")
def data_canonicalise(
    dataset: str | None = typer.Option(None, help="cicids2017 | cseids2018 | all"),
) -> None:
    """Stream raw CSVs to canonical per-day parquet."""
    from nids.data.loaders import canonicalise_all
    from nids.data.schema import Dataset

    s = get_settings()
    ds = None if dataset in (None, "all") else (Dataset(dataset),)
    written = canonicalise_all(s.raw_dir, s.processed_dir, ds)
    for p in written:
        console.print(f"wrote {p}")
    if not written:
        raise typer.Exit(code=1)


@data_app.command("clean")
def data_clean() -> None:
    """Stream-clean every canonical day into data/processed/clean (one day in memory at a time)."""
    from nids.data.loaders import iter_day_files
    from nids.data.profile import clean_day

    s = get_settings()
    total = {"rows_in": 0, "rows_out": 0, "duplicates_dropped": 0}
    for day, _ in iter_day_files(s.processed_dir, "canonical"):
        rep = clean_day(day, s.processed_dir, force=True)
        console.print(f"{day.day}: {rep.rows_in:,} -> {rep.rows_out:,} rows")
        for k in total:
            total[k] += int(getattr(rep, k))
    console.print(total)


@data_app.command("validate")
def data_validate(
    strict: bool = typer.Option(False, help="Validate the clean stage and disallow inf/null"),
) -> None:
    """Validate every day file (one at a time) and write a JSON report."""
    import polars as pl

    from nids.data.loaders import Stage, iter_day_files
    from nids.data.validation import validate_canonical, write_ge_suite

    s = get_settings()
    stage: Stage = "clean" if strict else "canonical"
    days: dict[str, object] = {}
    passed = True
    for day, path in iter_day_files(s.processed_dir, stage):
        rep = validate_canonical(pl.scan_parquet(path), allow_inf=not strict)
        if strict:  # cleaning changes row counts by design
            rep.expectations = [
                e for e in rep.expectations if e.name != "row_counts_match_published"
            ]
        days[day.day] = rep.as_dict()
        passed = passed and rep.passed
        console.print(
            f"{day.day}: {'ok' if rep.passed else 'FAILED ' + str([e.name for e in rep.failures])}"
        )
    out = s.artifacts_root / "reports" / f"validation_{stage}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps({"stage": stage, "passed": passed, "days": days}, indent=2, default=str)
    )
    write_ge_suite(s.artifacts_root / "reports" / "great_expectations_suite.json")
    if not days or not passed:
        raise typer.Exit(code=1)


@data_app.command("profile")
def data_profile(card: Path = typer.Option(Path("docs/DATA_CARD.md"))) -> None:
    """Compute measured statistics day by day and update the data card."""
    from nids.data.profile import profile_dir, update_data_card

    s = get_settings()
    p = profile_dir(s.processed_dir)
    update_data_card(card, p, s.artifacts_root / "reports" / "data_profile.json")
    console.print(f"updated {card}")


@data_app.command("split")
def data_split(
    holdout_days: str = typer.Option("", help="comma-separated day ids to hold out"),
    holdout_datasets: str = typer.Option("", help="comma-separated dataset ids to hold out"),
) -> None:
    """Split the clean stage per day (temporal, group-aware) with a cross-day purge."""
    from nids.data.splits import SplitConfig, split_dir

    s = get_settings()
    cfg = SplitConfig(
        holdout_days=tuple(x for x in holdout_days.split(",") if x),
        holdout_datasets=tuple(x for x in holdout_datasets.split(",") if x),
    )
    summary = split_dir(s.processed_dir, cfg)
    out = s.artifacts_root / "reports" / "split_summary.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    summary.write_csv(out)
    console.print(summary)


if __name__ == "__main__":
    app()
