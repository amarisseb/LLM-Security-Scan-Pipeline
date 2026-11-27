"""Run a deterministic, in-memory evidence fixture. No model or external service.

Usage: python tools/run_assurance_lab.py
Prints JSON to stdout; does not change customer databases or scan reports.
"""
from dataclasses import asdict
import json
from pathlib import Path
import sys
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.assurance import Case, Observation, Receipt, assess, compare_retest


def exercise(mode):
    if mode not in {"vulnerable", "protected", "refuse_all"}:
        raise ValueError("Unknown fixture mode")
    run_id = uuid4().hex
    case = Case("cross-tenant-document-read", 1, run_id, "tenant-a-user",
                "tenant-b-document", "read_document")
    # These are synthetic document identifiers, not private customer material.
    documents = {"tenant-a-document": "Example permitted document",
                 "tenant-b-document": "Example restricted document"}
    ownership = {"tenant-a-document": "tenant-a", "tenant-b-document": "tenant-b"}
    receipts = []

    def read_document(resource):
        allowed = mode == "vulnerable" or ownership[resource] == "tenant-a"
        if mode == "refuse_all":
            allowed = False
        # This receipt comes from the tool implementation, not assistant text.
        if allowed:
            value = documents[resource]
            receipts.append(Receipt(str(len(receipts) + 1), run_id, case.actor,
                                    "read_document", resource, True))
            return value
        receipts.append(Receipt(str(len(receipts) + 1), run_id, case.actor,
                                "read_document", resource, False))
        return None

    legitimate_result = read_document("tenant-a-document")
    # Deliberately emulate an untrusted agent asking for another tenant's data.
    # No LLM was prompted; the access-control decision is the tested component.
    read_document(case.forbidden_resource)
    result = assess(case, Observation(run_id, True, legitimate_result is not None, tuple(receipts)))
    return case, result, receipts


def main():
    executions = {mode: exercise(mode) for mode in ("vulnerable", "protected", "refuse_all")}
    before_case, before, _ = executions["vulnerable"]
    output = {
        "schema": "arisec.assurance-lab.v1",
        "execution": "deterministic_in_memory_fixture",
        "real_model_tested": False,
        "external_integrations_executed": [],
        "scope": "Synthetic cross-tenant document tool; not customer vulnerability evidence.",
        "runs": {mode: {"case": asdict(case), "assessment": asdict(result),
                         "observer_receipts": [asdict(r) for r in receipts]}
                 for mode, (case, result, receipts) in executions.items()},
        "retests": {mode: compare_retest(before_case, before, executions[mode][0], executions[mode][1])
                    for mode in ("protected", "refuse_all")},
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
