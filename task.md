# AirSentry Phase 3 — Task Checklist

## Planning
- [x] Analyze existing Phase 1 & 2 codebase
- [x] Read detection engine, rolling window, event models, alerts, CLI, settings, JSONL logger
- [x] Write implementation plan
- [x] User review and approval

## New Modules / Files

### airsentry/analysis/ (new package)
- [x] `__init__.py`
- [x] `features.py` — FeatureVector dataclass + extractor
- [ ] `extractors/` — modular per-feature extractors
  - [ ] `__init__.py`
  - [ ] `base.py` — abstract Extractor base class
  - [ ] `beacon_extractor.py`
  - [ ] `probe_extractor.py`
  - [ ] `deauth_extractor.py`
  - [ ] `device_extractor.py`
- [x] `scoring.py` — AnomalyScorer (IsolationForest / fallback heuristic)
- [x] `window_aggregator.py` — event window → feature vector adapter

### airsentry/research/ (new package)
- [x] `__init__.py`
- [x] `collector.py` — ResearchCollector (periodic snapshots)
- [x] `exporter.py` — CSV/JSONL dataset export
- [x] `privacy.py` — MAC anonymization utilities

### airsentry/cli/commands/
- [x] `collect.py` — `airsentry collect` subcommand

### airsentry/models/
- [x] `analysis.py` — WindowStats / ScoredWindow dataclasses (already in analysis/models.py)

### airsentry/config/settings.py
- [x] Add AnalysisSettings and ResearchSettings sections

### airsentry/output/console.py
- [x] Add `print_window_stats()` for anomaly score display

### airsentry/cli/main.py
- [x] Register `collect` subcommand

### pyproject.toml
- [x] Add `scikit-learn` and `numpy` to dependencies

## Verification
- [x] Run `pip install -e .` to confirm no import errors
- [x] Run replay mode to verify existing behavior unchanged
- [x] Run `airsentry collect --help` to verify new CLI
- [x] Manual replay with anomaly scoring enabled — verify window stats printed
- [x] Verify JSONL/CSV export output structure
