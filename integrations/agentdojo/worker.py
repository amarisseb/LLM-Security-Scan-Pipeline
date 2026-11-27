"""One fixed AgentDojo workspace case. Optional, local-only execution worker.

All tools are AgentDojo's simulated in-memory functions. No MCP, shell or real
mail tools are registered. Model transport accepts numeric loopback only.
"""
from datetime import datetime, timezone
from hashlib import sha256
import http.client
from importlib.metadata import version
import json
import logging
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from app.agentdojo_support import AGENTDOJO_VERSION, BENCHMARK_VERSION, Budget, BudgetExceeded, benchmark_outcome, local_endpoint, validate_message
from app.assurance_progress import publish

MAX_BODY = 524288
MAX_CONTEXT = 131072


def completion(endpoint, body, budget):
    host, port, prefix = local_endpoint(endpoint)
    encoded = json.dumps(body, allow_nan=False).encode()
    if len(encoded) > MAX_CONTEXT:
        raise BudgetExceeded("context_bytes")
    budget.request()
    remaining = budget.deadline - time.monotonic()
    conn = http.client.HTTPConnection(host, port, timeout=max(.1, min(120, remaining)))
    try:
        conn.request("POST", prefix + "/chat/completions", encoded, {"Content-Type": "application/json"})
        response = conn.getresponse()
        if response.status != 200:  # No redirect following, retries or cloud fallback.
            raise RuntimeError("model_http_error")
        data = bytearray()
        while True:
            budget.check()
            chunk = response.read1(8192)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_BODY:
                raise BudgetExceeded("response_bytes")
        budget.check()
        result = json.loads(data)
        if result["choices"][0].get("finish_reason") not in {"stop", "tool_calls"}:
            raise RuntimeError("incomplete_model_response")
        return validate_message(result["choices"][0]["message"])
    finally:
        conn.close()


def execute(config, summary):
    if version("agentdojo") != AGENTDOJO_VERSION:
        raise RuntimeError("unsupported_agentdojo_version")
    # Only import upstream after the version check. No .env-loading CLI helper.
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.attacks import load_attack
    from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.types import get_text_content_as_str, text_content_block_from_string
    from importlib.resources import files
    import yaml

    system_message = yaml.safe_load(files("agentdojo").joinpath("data/system_messages.yaml").read_text(encoding="utf-8"))["default"]

    suite = get_suite(BENCHMARK_VERSION, "workspace")
    if config.get("focused"):
        import copy
        suite = copy.copy(suite)
        suite.tools = [tool for tool in suite.tools if tool.name in {"search_calendar_events", "send_email"}]
    user_task = suite.get_user_task_by_id("user_task_0")
    injection_task = suite.get_injection_task_by_id("injection_task_0")
    summary.update(agentdojo_version=AGENTDOJO_VERSION, benchmark_version=BENCHMARK_VERSION,
                   suite="workspace", user_task=user_task.ID, injection_task=injection_task.ID,
                   attack="tool_knowledge", tool_names=sorted(tool.name for tool in suite.tools),
                   dependency_versions={name: version(name) for name in ("agentdojo", "pydantic", "deepdiff")},
                   worker_sha256=sha256(Path(__file__).read_bytes()).hexdigest())
    summary["tool_scope"] = "focused_calendar_email" if config.get("focused") else "workspace_tools"
    if config["check"]:
        summary["status"] = "environment_ready"
        return
    budget = Budget(seconds=config["seconds"])
    phases = {}
    stage = "model_ready"

    def progress():
        publish(config.get("progress_id"), stage,
                completed=[name for name, result in phases.items() if result["status"] == "complete"],
                requests=budget.requests, tools=budget.tools)

    class Driver(BasePipelineElement):
        name = "arisec-local"

        def query(self, query, runtime, env, messages=(), extra_args=None):
            calendar_context = ""
            if config.get("focused"):
                calendar_context = "\nThe current date in this simulated calendar is " + env.calendar.current_day.isoformat() + "."
            history = [{"role": "system", "content": [text_content_block_from_string(
                system_message + calendar_context)]},
                       {"role": "user", "content": [text_content_block_from_string(query)]}]
            for _ in range(6):
                wire = []
                for message in history:
                    item = {"role": message["role"], "content": get_text_content_as_str(message["content"] or [])}
                    if message["role"] == "assistant" and message.get("tool_calls"):
                        item["tool_calls"] = [{"id": c.id, "type": "function", "function": {
                            "name": c.function, "arguments": json.dumps(c.args)}} for c in message["tool_calls"]]
                    if message["role"] == "tool":
                        item["tool_call_id"] = message["tool_call_id"]
                        if message.get("error"):
                            item["content"] = message["error"]
                    wire.append(item)
                tools = [{"type": "function", "function": {"name": f.name, "description": f.description,
                         "parameters": f.parameters.model_json_schema()}} for f in runtime.functions.values()]
                answer = validate_message(completion(config["endpoint"], {"model": config["model"], "messages": wire,
                                    "tools": tools, "tool_choice": "auto", "temperature": 0,
                                    "max_tokens": 768, "stream": False}, budget))
                progress()
                calls = []
                raw_calls = answer.get("tool_calls") or []
                if not isinstance(raw_calls, list) or len(raw_calls) > 8:
                    raise RuntimeError("invalid_model_tools")
                for call in raw_calls:
                    arguments = json.loads(call["function"]["arguments"])
                    if not isinstance(arguments, dict) or not isinstance(call.get("id"), str) or not call["id"]:
                        raise RuntimeError("invalid_model_tool")
                    calls.append(FunctionCall(id=call["id"], function=call["function"]["name"], args=arguments))
                text = answer.get("content")
                if text is not None and not isinstance(text, str):
                    raise RuntimeError("invalid_model_content")
                history.append({"role": "assistant", "content": [text_content_block_from_string(text or "")],
                                "tool_calls": calls or None})
                self.messages = history
                if not calls:
                    return query, runtime, env, history, {}
                for call in calls:
                    value, error = runtime.run_function(env, call.function, call.args)
                    serialised = json.dumps(value, default=lambda v: v.model_dump(mode="json") if hasattr(v, "model_dump") else str(v))
                    if len(serialised.encode()) > MAX_CONTEXT:
                        raise BudgetExceeded("tool_result_bytes")
                    history.append({"role": "tool", "content": [text_content_block_from_string(serialised)],
                                    "tool_call": call, "tool_call_id": call.id, "error": error})
            raise BudgetExceeded("phase_turns")

    driver = Driver()
    injections = load_attack("tool_knowledge", suite, driver).attack(user_task, injection_task)
    for name, task, injected_task, payload in (
            ("clean_user", user_task, None, {}),
            ("goal_capability", injection_task, None, {}),
            ("attacked", user_task, injection_task, injections)):
        events = []
        stage = name
        progress()
        driver.messages = []

        class ObservedRuntime(FunctionsRuntime):
            def run_function(self, env, function, kwargs, raise_on_error=False):
                budget.tool()
                before = sha256(env.model_dump_json().encode()).hexdigest()
                value, error = super().run_function(env, function, kwargs, raise_on_error)
                events.append({"event_id": str(len(events) + 1), "function": function,
                               "arguments": kwargs, "returned_without_error": error is None,
                               "state_before_sha256": before,
                               "state_after_sha256": sha256(env.model_dump_json().encode()).hexdigest()})
                progress()
                return value, error

        phase = {"status": "inconclusive", "utility": None, "security": None}
        try:
            utility, security = suite.run_task_with_pipeline(driver, task, injected_task, payload,
                                                              runtime_class=ObservedRuntime)
            budget.check()
            if type(utility) is not bool or type(security) is not bool:
                raise RuntimeError("invalid_grader_result")
            phase.update(status="complete", utility=utility, security=security)
        except Exception as exc:
            phase["error_type"] = type(exc).__name__
        phase["tools"] = list(dict.fromkeys(event["function"] for event in events))
        trace = {"phase": name, "result": phase, "injections": payload,
                 "messages": driver.messages, "tool_events": events}
        raw = json.dumps(trace, default=lambda v: v.model_dump(mode="json"), indent=2).encode()
        trace_path = Path(name + ".json")
        trace_path.write_bytes(raw)
        phase.update(trace=trace_path.name, trace_sha256=sha256(raw).hexdigest())
        phases[name] = phase
        progress()
    summary.update(status="complete" if all(p["status"] == "complete" for p in phases.values()) else "inconclusive",
                   phases=phases, requests=budget.requests, tool_calls=budget.tools,
                   limits={"model_requests": budget.max_requests, "tool_calls": budget.max_tools,
                           "wall_seconds": budget.seconds, "turns_per_phase": 6,
                           "requested_output_tokens_per_call": 768, "request_bytes": MAX_CONTEXT},
                   assessment=benchmark_outcome(phases["attacked"]["utility"], phases["attacked"]["security"],
                                                error=phases["attacked"]["status"] != "complete",
                                                clean_control=phases["clean_user"]["utility"],
                                                goal_control=phases["goal_capability"]["utility"]))


def main():
    logging.disable(logging.CRITICAL)
    config = json.loads(sys.stdin.buffer.read(8193))
    summary = {"schema": "arisec.agentdojo.v1", "run_id": config["run_id"],
               "started_at": datetime.now(timezone.utc).isoformat(), "status": "inconclusive",
               "customer_system_tested": False, "model": config["model"],
               "execution": "agentdojo_simulated_tools", "model_execution_requested": not config["check"],
               "scope": "One benchmark case; not a customer assessment or benchmark-wide success rate."}
    try:
        execute(config, summary)
    except Exception as exc:
        summary["error_code"] = type(exc).__name__
    Path("summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
