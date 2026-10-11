"""Run garak's probes against a web chat page, using garak's Python API.

Produces the standard garak.<run_id>.report.jsonl (plus the .hitlog.jsonl beside
it) that generate_report.py and audit_report.py already read unmodified.

Usage from code:
    report_path = run_scan("https://example.com/chat", "garak_runs/my-scan")

Usage from a shell:
    python -m app.run_scan https://example.com/chat --output-dir garak_runs/my-scan
"""

import argparse
import contextlib
import datetime
import json
import logging
import os
import random
import threading
from pathlib import Path

import garak.evaluators
from garak import _config, _plugins, command
from garak.exception import BadGeneratorException

from . import browser_generator  # noqa: F401  (registers generators.browser with garak)
from .browser_generator import AiNotConfirmed

logger = logging.getLogger(__name__)

# ---- direct API-key scanning --------------------------------------------
#
# garak's LiteLLM generator is the one piece of garak that talks to a provider
# API directly rather than through a browser. litellm resolves a provider from
# the "provider/model" name and reads credentials from environment variables
# (OPENAI_API_KEY and so on) -- it never reads a config value for this: the
# generator code calls litellm.completion() without ever passing api_key, so
# setting one via _config would do nothing anyway. The only other way to hand
# it a key is through _config.plugins.generators, which command.start_run()
# serializes verbatim into report.jsonl's "start_run setup" entry -- so a key
# placed there would be written to disk in plain text. This module therefore
# never puts a key into _config: it goes in only as an environment variable,
# for the duration of the locked scan, via _with_env_var below.
#
# litellm also accepts a user-settable api_base override, which would let a
# caller point the "API" at an internal address -- the exact SSRF class
# url_safety.py exists to block, reopened through a new door. So api_base is
# never exposed here: only a fixed, known provider name from this map, which
# litellm resolves to its own built-in endpoint.
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
) -> Path:
    """Scan `target_url` and return the path of the report.jsonl.

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
    with _RUN_LOCK:
        return _run_scan(
            target_url,
            Path(output_dir),
            generations,
            prompt_cap,
            generator_options or {},
            on_progress,
            require_ai_confirmation,
        )


def _run_scan(
    target_url, output_dir, generations, prompt_cap, generator_options, on_progress,
    require_ai_confirmation,
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
    # garak's promptinject probes reseed Python's RNG from run.seed (None by
    # default, i.e. from entropy) while choosing their prompts.
    _config.run.seed = SAMPLE_SEED
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
) -> Path:
    """Scan a model directly through its provider's API and return the path of
    the report.jsonl. `provider` must be a key of PROVIDER_API_KEY_ENV_VAR.

    `api_key` lives only in memory for the duration of this call: see the
    module docstring note above PROVIDER_API_KEY_ENV_VAR for why it is never
    written to garak's config or logged. Raises UnsupportedProvider for an
    unknown provider, ApiAuthError if the provider rejects the key, or
    whatever garak/litellm raises for any other failure.
    """
    if provider not in PROVIDER_API_KEY_ENV_VAR:
        raise UnsupportedProvider(provider)
    with _RUN_LOCK:
        return _run_api_scan(
            provider, model, api_key, Path(output_dir), generations, prompt_cap, on_progress
        )


def _run_api_scan(provider, model, api_key, output_dir, generations, prompt_cap, on_progress) -> Path:
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
    _config.run.soft_probe_prompt_cap = prompt_cap
    _config.run.seed = SAMPLE_SEED
    _config.reporting.report_dir = str(output_dir)

    full_name = f"{provider}/{model}"
    _config.plugins.target_type = "litellm"
    _config.plugins.target_name = full_name
    _config.plugins.probe_spec = ",".join(PROBES)
    # Replaced wholesale, not merged, and holding only `name`: see the note
    # above PROVIDER_API_KEY_ENV_VAR for why no key or api_base goes here.
    _config.plugins.generators["litellm"] = {"name": full_name}

    probe_names, unknown = _config.parse_plugin_spec(_config.plugins.probe_spec, "probes")
    if unknown:
        raise ValueError(f"unknown garak probes (garak version mismatch?): {unknown}")

    evaluator = garak.evaluators.ThresholdEvaluator(_config.run.eval_threshold)
    env_var = PROVIDER_API_KEY_ENV_VAR[provider]
    with _with_env_var(env_var, api_key):
        generator = _plugins.load_plugin("generators.litellm", config_root=_config)
        try:
            return _run_probes(generator, probe_names, evaluator, prompt_cap, on_progress)
        except BadGeneratorException as e:
            if _caused_by_auth_failure(e):
                raise ApiAuthError(f"{provider} rejected the API key") from e
            raise
        finally:
            if hasattr(generator, "close"):
                generator.close()


def _caused_by_auth_failure(exc: BaseException) -> bool:
    """True if a BadGeneratorException wraps litellm's AuthenticationError.
    garak collapses every litellm failure into one exception type and a fixed
    message, so the only way to tell a bad key apart from any other failure
    (rate limit, model not found, provider outage) is the original cause."""
    try:
        import litellm

        return isinstance(exc.__cause__, litellm.exceptions.AuthenticationError)
    except Exception:
        return False  # never let detection itself hide the real error


@contextlib.contextmanager
def _with_env_var(name: str, value: str):
    """Set an environment variable for the duration of the block, then put
    back exactly what was there before (or remove it if it wasn't set).

    This is the only place an API key touches process state. Scans are
    already serialized by _RUN_LOCK, which is what makes a process-wide
    env var safe to use as a handoff: no other scan can be mid-run to see it
    change underfoot, and nothing else in this app reads these names.
    """
    missing = object()
    previous = os.environ.get(name, missing)
    os.environ[name] = value
    try:
        yield
    finally:
        if previous is missing:
            os.environ.pop(name, None)
        else:
            os.environ[name] = previous


def _run_probes(generator, probe_names, evaluator, prompt_cap, on_progress) -> Path:
    """The part of a scan that is identical regardless of how the generator
    talks to its target: install the prompt cap, run every probe, restore
    garak's loader, and return the report path."""
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
        if str(path).startswith("probes."):
            random.seed(SAMPLE_SEED)  # garak samples with the global RNG when building a probe
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
