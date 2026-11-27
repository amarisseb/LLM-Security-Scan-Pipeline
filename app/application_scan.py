"""Run the existing probe suite against an application's JSON endpoint."""

import datetime
from pathlib import Path

import garak.evaluators
from garak import _config

from . import run_scan as engine
from .application_generator import ApplicationGenerator


def run_application_scan(url, request_template, response_path, api_key, output_dir, on_progress=None,
                         *, prompt_cap=engine.DEFAULT_PROMPT_CAP, scenario_sector="general",
                         scan_profile="full"):
    profile_probes = engine.profile_probes(scan_profile)
    if scan_profile == "free" and scenario_sector != "general":
        raise ValueError("Free scan profile requires general scenarios")
    from .sector_probes import sector_plugins

    extra_probes, registry = sector_plugins(scenario_sector)
    if type(prompt_cap) is not int or not 1 <= prompt_cap <= 100:
        raise ValueError("prompt_cap must be an integer from 1 to 100")
    with engine._RUN_LOCK:
        output_dir = Path(output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        engine._make_output_encoding_safe()
        engine._reset_garak_state()
        _config.load_base_config()
        now = datetime.datetime.now()
        _config.transient.starttime = now
        _config.transient.starttime_iso = now.isoformat()
        _config.system.lite = False
        _config.system.parallel_attempts = False
        _config.system.parallel_requests = False
        _config.run.generations = engine.DEFAULT_GENERATIONS
        _config.run.scan_profile = scan_profile
        _config.run.soft_probe_prompt_cap = prompt_cap
        _config.run.seed = engine.SAMPLE_SEED
        _config.reporting.report_dir = str(output_dir)
        _config.plugins.target_type = "application"
        _config.plugins.target_name = url
        _config.plugins.probe_spec = ",".join(profile_probes)
        probes, unknown = _config.parse_plugin_spec(_config.plugins.probe_spec, "probes")
        if unknown:
            raise ValueError("Unavailable probes")
        probes = list(probes) + extra_probes
        if extra_probes:
            _config.plugins.probe_spec = ",".join(probes)
        generator = ApplicationGenerator(url, request_template, response_path, api_key)
        evaluator = garak.evaluators.ThresholdEvaluator(_config.run.eval_threshold)
        try:
            return engine._run_probes(generator, probes, evaluator, prompt_cap, on_progress,
                                      local_registry=registry)
        finally:
            generator.close()
