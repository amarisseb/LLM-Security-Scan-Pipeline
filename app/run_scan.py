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
import json
import logging
import random
import threading
from pathlib import Path

import garak.evaluators
from garak import _config, _plugins, command

logger = logging.getLogger(__name__)

# ---- direct API-key scanning --------------------------------------------
#
# Kept as a public provider allowlist for existing callers. Credentials are
# passed directly to the runtime generator, never through environment/config.
PROVIDER_API_KEY_ENV_VAR = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "groq": "GROQ_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "cohere": "COHERE_API_KEY",
}


class UnsupportedProvider(ValueError):
    """`provider` isn't in PROVIDER_API_KEY_ENV_VAR. Safe to show the caller."""


class ApiAuthError(RuntimeError):
    """The provider rejected the API key. Safe to show the caller."""

PROBES = [
    "promptinject",
    "dan",
    "encoding",
    "sysprompt_extraction",
    # Inactive by default in garak, so it has to be named in full.
    "donotanswer.MaliciousUses",
]


def profile_probes(scan_profile="full"):
    """Select a server profile, never a caller-supplied garak plugin spec.

    Free is one attack family (with the configured per-probe prompt cap).
    Full keeps the existing five families; it does not mean every garak probe.
    """
    if type(scan_profile) is not str or scan_profile not in ("free", "full"):
        raise ValueError("Unknown scan profile")
    return ["promptinject"] if scan_profile == "free" else list(PROBES)

# garak's own defaults (5 generations of up to 256 prompts per probe) assume a
# fast API. Through a browser each prompt takes several seconds, so those
# defaults would run for many hours. Raise these for a deeper, slower scan.
#
# garak's soft_probe_prompt_cap is only honoured by most probes:
# dan.Ablation_Dan_11_0 (127 prompts) and donotanswer.MaliciousUses (243) ignore
# it. _enforce_prompt_cap below closes that gap, so the cap really is a cap.
DEFAULT_GENERATIONS = 1
DEFAULT_PROMPT_CAP = 10

# Written next to the report: whether the target answered a simple question like
# an AI would. See BrowserGenerator.responds_like_ai.
TARGET_CHECK_FILE = "target_check.json"

# Which prompts a probe uses is seeded, not a fresh random draw, so re-scanning
# after a fix tests the same prompts. garak's own sampling uses the global
# `random`, so it is seeded just before each probe is created (see _capping_loader).
SAMPLE_SEED = 20250101  # non-zero: some code treats a seed of 0 as "no seed"

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
    require_ai_confirmation: bool = True,
    scan_profile: str = "full",
) -> Path:
    """Scan `target_url` and return the path of the report.jsonl.

    scan_profile="free" selects only the prompt-injection family; "full"
    preserves the existing five-family suite. Prompt caps apply independently.

    on_progress(index, total, probe_name), if given, is called as each probe
    starts (index counts from 1), e.g. (7, 23, "probes.encoding.InjectBase64").

    generator_options tunes BrowserGenerator for this target, e.g.
    {"settle_ms": 6000} for a bot that pauses mid-answer.

    Before any attack is sent, the page is asked two simple questions. If it
    doesn't answer them like an AI, the scan stops with AiNotConfirmed, so a
    login form, contact form or search box isn't sent hundreds of attack
    messages. A tightly scoped assistant may refuse those questions, so the
    caller can pass require_ai_confirmation=False to scan anyway; the report
    then carries a caveat.

    Raises if the target can't be driven (unsafe URL, no chat input found) or
    the run fails partway; a half-finished report file is left in output_dir.
    """
    profile_probes(scan_profile)
    profile_options = {"scan_profile": scan_profile} if scan_profile != "full" else {}
    with _RUN_LOCK:
        return _run_scan(
            target_url,
            Path(output_dir),
            generations,
            prompt_cap,
            generator_options or {},
            on_progress,
            require_ai_confirmation,
            **profile_options,
        )


def _run_scan(
    target_url, output_dir, generations, prompt_cap, generator_options, on_progress,
    require_ai_confirmation, scan_profile="full",
) -> Path:
    probes = profile_probes(scan_profile)
    from . import browser_generator  # noqa: F401 (registers the browser plugin)
    from .browser_generator import AiNotConfirmed

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
    _config.run.scan_profile = scan_profile
    _config.run.soft_probe_prompt_cap = prompt_cap
    # garak's promptinject probes reseed Python's RNG from run.seed (None by
    # default, i.e. from entropy) while choosing their prompts.
    _config.run.seed = SAMPLE_SEED
    _config.reporting.report_dir = str(output_dir)

    # The same settings `--target_type browser --target_name <url>` would make.
    _config.plugins.target_type = "browser"
    _config.plugins.target_name = target_url
    _config.plugins.probe_spec = ",".join(probes)
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
        # Recorded beside the report, not in it: the report stays a plain garak file.
        ai_confirmed = generator.responds_like_ai()
        (output_dir / TARGET_CHECK_FILE).write_text(
            json.dumps({"ai_confirmed": ai_confirmed}), encoding="utf-8"
        )
        if require_ai_confirmation and not ai_confirmed:
            raise AiNotConfirmed("target did not answer simple questions like an AI")
        return _run_probes(generator, probe_names, evaluator, prompt_cap, on_progress)
    finally:
        generator.close()


def run_api_scan(
    provider: str,
    model: str,
    api_key: str,
    output_dir: str | Path,
    *,
    generations: int = DEFAULT_GENERATIONS,
    prompt_cap: int = DEFAULT_PROMPT_CAP,
    on_progress=None,
    scan_profile: str = "full",
) -> Path:
    """Scan a model directly through its provider's API and return the path of
    the report.jsonl. `provider` must be a key of PROVIDER_API_KEY_ENV_VAR.

    scan_profile is the server-selected "free" (prompt injection only) or
    "full" (the existing five families), independently of the prompt cap.

    The key is supplied only to an isolated runtime HTTP client. Raises
    UnsupportedProvider for an unknown provider, ApiAuthError for rejected
    credentials, or a sanitized BadGeneratorException for request failures.
    Requests have no retries and scans check a cooperative wall-clock budget.
    """
    profile_probes(scan_profile)
    from .provider_generator import validate_target

    if provider not in PROVIDER_API_KEY_ENV_VAR:
        raise UnsupportedProvider("unsupported provider")
    validate_target(provider, model, api_key)
    profile_options = {"scan_profile": scan_profile} if scan_profile != "full" else {}
    with _RUN_LOCK:
        return _run_api_scan(
            provider, model, api_key, Path(output_dir), generations, prompt_cap, on_progress,
            **profile_options,
        )


def _run_api_scan(provider, model, api_key, output_dir, generations, prompt_cap, on_progress,
                  scan_profile="full") -> Path:
    probes = profile_probes(scan_profile)
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    _make_output_encoding_safe()
    _reset_garak_state()
    _config.load_base_config()
    now = datetime.datetime.now()
    _config.transient.starttime = now
    _config.transient.starttime_iso = now.isoformat()

    _config.system.lite = False
    _config.run.generations = generations
    _config.run.scan_profile = scan_profile
    _config.run.soft_probe_prompt_cap = prompt_cap
    _config.run.seed = SAMPLE_SEED
    _config.reporting.report_dir = str(output_dir)

    full_name = f"{provider}/{model}"
    _config.plugins.target_type = "direct_provider"
    _config.plugins.target_name = full_name
    _config.plugins.probe_spec = ",".join(probes)
    # Only public target metadata enters the standard garak setup report.
    _config.plugins.generators["direct_provider"] = {"name": full_name}
    _config.system.parallel_requests = 1
    _config.system.parallel_attempts = 1

    probe_names, unknown = _config.parse_plugin_spec(_config.plugins.probe_spec, "probes")
    if unknown:
        raise ValueError(f"unknown garak probes (garak version mismatch?): {unknown}")

    from .provider_generator import ProviderGenerator

    evaluator = garak.evaluators.ThresholdEvaluator(_config.run.eval_threshold)
    generator = ProviderGenerator(provider, model, api_key)
    try:
        result = _run_probes(generator, probe_names, evaluator, prompt_cap, on_progress)
        generator.check_deadline()
        return result
    finally:
        generator.close()


def _run_probes(generator, probe_names, evaluator, prompt_cap, on_progress, local_registry=None) -> Path:
    """The part of a scan that is identical regardless of how the generator
    talks to its target: install the prompt cap, run every probe, restore
    garak's loader, and return the report path."""
    command.start_run()
    real_load_plugin = _plugins.load_plugin
    real_plugin_info = _plugins.PluginCache.plugin_info
    if local_registry:
        def runtime_plugin_info(plugin):
            if isinstance(plugin, str) and plugin in local_registry:
                return real_plugin_info(local_registry[plugin])
            return real_plugin_info(plugin)
        _plugins.PluginCache.plugin_info = staticmethod(runtime_plugin_info)
    _plugins.load_plugin = _capping_loader(
        real_load_plugin, prompt_cap, on_progress, total_probes=len(probe_names),
        check_deadline=getattr(generator, "check_deadline", None),
        local_registry=local_registry,
    )
    try:
        command.probewise_run(generator, probe_names, evaluator, [])
        if hasattr(generator, "check_deadline"):
            generator.check_deadline()
    except BaseException:
        _close_report_file()
        raise
    finally:
        _plugins.load_plugin = real_load_plugin
        _plugins.PluginCache.plugin_info = staticmethod(real_plugin_info)
    command.end_run()
    return Path(_config.transient.report_filename)


def _capping_loader(load_plugin, cap, on_progress=None, total_probes=0, check_deadline=None,
                    local_registry=None):
    """Wrap garak's plugin loader so every probe it hands back respects `cap`.

    The harness loads probes by name, so this is the one place to intervene
    without editing garak. It is installed only for the duration of a scan.
    The harness loads each probe just before running it, which is also what
    makes this the natural place to report progress.
    """
    started = 0

    def load(path, *args, **kwargs):
        nonlocal started
        if check_deadline:
            check_deadline()
        if str(path).startswith("probes."):
            random.seed(SAMPLE_SEED)  # garak samples with the global RNG when building a probe
        if local_registry and path in local_registry:
            plugin = local_registry[path](config_root=kwargs.get("config_root", _config))
        else:
            plugin = load_plugin(path, *args, **kwargs)
        if plugin and str(path).startswith("probes."):
            _enforce_prompt_cap(plugin, str(path), cap)
            started += 1
            if on_progress:
                try:
                    on_progress(started, total_probes, str(path))
                except Exception:
                    if check_deadline:
                        logger.error("progress callback failed")
                    else:
                        logger.exception("progress callback failed")
        if check_deadline:
            check_deadline()
        return plugin

    return load


def _enforce_prompt_cap(probe, name, cap):
    prompts = getattr(probe, "prompts", None)
    if not isinstance(prompts, (list, tuple)) or len(prompts) <= cap:
        return
    keep = sorted(random.Random(SAMPLE_SEED).sample(range(len(prompts)), cap))
    probe.prompts = [prompts[i] for i in keep]
    triggers = getattr(probe, "triggers", None)
    if isinstance(triggers, (list, tuple)) and len(triggers) == len(prompts):
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
    # Otherwise a stale entry (e.g. a previous scan's model name) sits in the
    # dict that command.start_run() dumps into the new report's setup entry.
    _config.plugins.generators.clear()
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
