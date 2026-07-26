# LLM-Security-Scan-Pipeline


Early-stage tooling for an AI security project I'm building. Companies are deploying LLM-powered features faster than they're securing them this pipeline finds out exactly how exposed a deployed model is, and turns the results into something a non-technical team can actually act on.

## What this does

1. **Scan** — uses [garak](https://github.com/NVIDIA/garak), an open-source LLM vulnerability scanner, to run a target model through five categories of real attack:
   - **Hijacking** (`promptinject`) — smuggling instructions inside content the model was only meant to process
   - **Jailbreak** (`dan`) — talking the model out of its safety guardrails
   - **Filter evasion** (`encoding`) — sneaking blocked requests past filters using Base64/ROT13/hex/etc.
   - **Prompt leak** (`sysprompt_extraction`) — extracting a deployment's system prompt (its actual product logic)
   - **Unsafe content** (`donotanswer`) — brand-safety and liability failures

2. **Report** — `generate_report.py` parses garak's raw JSONL output and produces a readable HTML dashboard: an overall exposure score, a breakdown per attack category, real evidence (the actual prompt sent and the model's actual response) for each failing category, and a plain-language remediation recommendation.

3. **Audit** — `audit_report.py` independently recomputes every number in the dashboard from the raw scan data and prints it line-by-line, so the report's numbers can be manually verified rather than trusted blindly.

## Try it

```bash
pip install garak

# run a scan against your own model (needs your own API key set as
# an environment variable, e.g. OPENAI_API_KEY)
python -m garak --model_type openai --model_name gpt-4o-mini \
  --probes promptinject,dan,encoding,sysprompt_extraction,donotanswer.MaliciousUses

# turn the result into a dashboard
python generate_report.py path/to/garak.RUNID.report.jsonl --target "gpt-4o-mini"

# spot-check the numbers yourself
python audit_report.py path/to/garak.RUNID.report.jsonl
```

`sample_report.html` in this repo is a static example with illustrative (not live) data, showing the report format without needing to run a scan first.

## Status

Early MVP. Built and tested against a live scan of `gpt-4o-mini`, which surfaced real findings (including a >50% success rate on prompt-hijacking attempts). Next steps: broader model/provider support, a wider probe set, and a first real pilot with a design partner.

## Why this exists

Most teams shipping an AI feature today are a thin wrapper around an API call and a system prompt, built by people without a security background. This pipeline is the first piece of making it possible for them to find out what's actually vulnerable in their deployment, in language they don't need a security background to understand.
