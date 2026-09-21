"""Run garak's probes against a web chat page, using garak's Python API.

Produces the standard garak.<run_id>.report.jsonl (plus the .hitlog.jsonl beside
it) that generate_report.py and audit_report.py already read unmodified.

Usage from code:
    report_path = run_scan("https://example.com/chat", "garak_runs/my-scan")

Usage from a shell:
    python -m app.run_scan https://example.com/chat --output-dir garak_runs/my-scan
"""

import argparse
import datetime
import logging
import random
import threading
from pathlib import Path

import garak.evaluators
from garak import _config, _plugins, command

from . import browser_generator  # noqa: F401  (registers generators.browser with garak)

logger = logging.getLogger(__name__)

PROBES = [
    "promptinject",
    "dan",
    "encoding",
    "sysprompt_extraction",
    # Inactive by default in garak, so it has to be named in full.
    "donotanswer.MaliciousUses",
]

# garak's own defaults (5 generations of up to 256 prompts per probe) assume a
# fast API. Through a browser each prompt takes several seconds, so those
# defaults would run for many hours. Raise these for a deeper, slower scan.
#
# garak's soft_probe_prompt_cap is only honoured by most probes:
# dan.Ablation_Dan_11_0 (127 prompts) and donotanswer.MaliciousUses (243) ignore
# it. _enforce_prompt_cap below closes that gap, so the cap really is a cap.
DEFAULT_GENERATIONS = 1
DEFAULT_PROMPT_CAP = 10

# Which prompts survive the cap is a seeded sample, not the first N or a fresh
# random draw, so re-scanning after a fix tests the same prompts.
SAMPLE_SEED = 0

# garak keeps its configuration and plugin instances in process-wide globals,
# so two scans can't run at the same time in one process.
_RUN_LOCK = threading.Lock()


def run_scan(
    target_url: str,
    output_dir: str | Path,
    *,
    generations: int = DEFAULT_GENERATIONS,
    prompt_cap: int = DEFAULT_PROMPT_CAP,
    generator_options: dict | None = None,
    on_progress=None,
) -> Path:
    """Scan `target_url` and return the path of the report.jsonl.

    on_progress(index, total, probe_name), if given, is called as each probe
    starts (index counts from 1), e.g. (7, 23, "probes.encoding.InjectBase64").

    generator_options tunes BrowserGenerator for this target, e.g.
    {"settle_ms": 6000} for a bot that pauses mid-answer.

    Raises if the target can't be driven (unsafe URL, no chat input found) or
    the run fails partway; a half-finished report file is left in output_dir.
    """
    with _RUN_LOCK:
        return _run_scan(
            target_url,
            Path(output_dir),
            generations,
            prompt_cap,
            generator_options or {},
            on_progress,
        )


def _run_scan(
    target_url, output_dir, generations, prompt_cap, generator_options, on_progress
) -> Path:
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    _make_output_encoding_safe()
    _reset_garak_state()
    _config.load_base_config()  # garak's shipped defaults only: no host site config
    now = datetime.datetime.now()
    _config.transient.starttime = now
    _config.transient.starttime_iso = now.isoformat()

    # `lite` only gates a CLI-only hint that reads CLI arguments we don't have.
    _config.system.lite = False
    _config.run.generations = generations
    _config.run.soft_probe_prompt_cap = prompt_cap
    _config.reporting.report_dir = str(output_dir)

    # The same settings `--target_type browser --target_name <url>` would make.
    _config.plugins.target_type = "browser"
    _config.plugins.target_name = target_url
    _config.plugins.probe_spec = ",".join(PROBES)
    _config.plugins.generators.setdefault("browser", {}).update(
        {**generator_options, "name": target_url}
    )

    probe_names, unknown = _config.parse_plugin_spec(_config.plugins.probe_spec, "probes")
    if unknown:
        raise ValueError(f"unknown garak probes (garak version mismatch?): {unknown}")

    evaluator = garak.evaluators.ThresholdEvaluator(_config.run.eval_threshold)
    generator = _plugins.load_plugin("generators.browser", config_root=_config)
    try:
        generator.preflight()  # fail fast if there's nothing to talk to
        command.start_run()
        real_load_plugin = _plugins.load_plugin
        _plugins.load_plugin = _capping_loader(
            real_load_plugin, prompt_cap, on_progress, total_probes=len(probe_names)
        )
        try:
            command.probewise_run(generator, probe_names, evaluator, [])
        except BaseException:
            _close_report_file()
            raise
        finally:
            _plugins.load_plugin = real_load_plugin
        command.end_run()
    finally:
        generator.close()

    return Path(_config.transient.report_filename)


def _capping_loader(load_plugin, cap, on_progress=None, total_probes=0):
    """Wrap garak's plugin loader so every probe it hands back respects `cap`.

    The harness loads probes by name, so this is the one place to intervene
    without editing garak. It is installed only for the duration of a scan.
    The harness loads each probe just before running it, which is also what
    makes this the natural place to report progress.
    """
    started = 0

    def load(path, *args, **kwargs):
        nonlocal started
        plugin = load_plugin(path, *args, **kwargs)
        if plugin and str(path).startswith("probes."):
            _enforce_prompt_cap(plugin, str(path), cap)
            started += 1
            if on_progress:
                try:
                    on_progress(started, total_probes, str(path))
                except Exception:
                    logger.exception("progress callback failed")  # never fail the scan for this
        return plugin

    return load


def _enforce_prompt_cap(probe, name, cap):
    prompts = getattr(probe, "prompts", None)
    if not isinstance(prompts, list) or len(prompts) <= cap:
        return
    keep = sorted(random.Random(SAMPLE_SEED).sample(range(len(prompts)), cap))
    probe.prompts = [prompts[i] for i in keep]
    triggers = getattr(probe, "triggers", None)
    if isinstance(triggers, list) and len(triggers) == len(prompts):
        probe.triggers = [triggers[i] for i in keep]  # stay aligned with prompts
    logger.info("%s: sampled %d of %d prompts", name, cap, len(prompts))


def _make_output_encoding_safe():
    """garak prints emoji. When stdout is a pipe or file on Windows (a service, a
    redirected log) Python encodes it as cp1252 and the print raises
    UnicodeEncodeError, which would abort the scan. Substitute instead of raising."""
    import sys

    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")


def _reset_garak_state():
    """Undo what the previous scan in this process left behind.

    garak caches plugin instances by class, so without this the second scan
    would silently reuse the first scan's generator (old URL, closed browser).
    """
    _plugins.PluginProvider._instance_cache.clear()
    _config.buffmanager.buffs = []
    _config.transient.report_filename = None
    _config.transient.reportfile = None
    _config.transient.hitlogfile = None


def _close_report_file():
    for handle in (_config.transient.reportfile, _config.transient.hitlogfile):
        if handle is not None and not handle.closed:
            handle.close()


def main():
    parser = argparse.ArgumentParser(description="Scan a web chat page with garak.")
    parser.add_argument("target_url")
    parser.add_argument("--output-dir", default="garak_runs")
    parser.add_argument("--generations", type=int, default=DEFAULT_GENERATIONS)
    parser.add_argument("--prompt-cap", type=int, default=DEFAULT_PROMPT_CAP)
    args = parser.parse_args()
    report = run_scan(
        args.target_url,
        args.output_dir,
        generations=args.generations,
        prompt_cap=args.prompt_cap,
    )
    print(f"report: {report}")


if __name__ == "__main__":
    main()
