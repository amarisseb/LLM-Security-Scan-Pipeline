"""Isolated browser QA. Default uses a job fixture; --real-local-test runs Qwen.

Never points at customer databases or calls customer/provider endpoints.
"""
import argparse
import copy
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
from unittest.mock import patch
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--real-local-test", action="store_true")
    args = parser.parse_args()
    import uvicorn
    from playwright.sync_api import sync_playwright
    with tempfile.TemporaryDirectory(prefix="assessment-ui-", dir=ROOT / ".venv") as temporary:
        folder = Path(temporary)
        os.environ['GARAK_LOG_FILE'] = os.devnull
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        url = f"http://127.0.0.1:{port}"
        os.environ.update(ARISEC_SELF_SERVE="1", ARISEC_LOCAL_PREVIEW="1", ARISEC_LOCAL_ASSURANCE="1",
                          ARISEC_LOCAL_DEMO="0", ARISEC_PROMPT_CAP="1", ARISEC_EXAMPLE_ENDPOINT=url + "/demo/endpoint",
                          ARISEC_ACCOUNTS_DB=str(folder / "accounts.sqlite3"), SCAN_OUTPUT_DIR=str(folder / "runs"),
                          ATTESTATION_LOG_PATH=str(folder / "attestations.jsonl"))
        from app import assessment_api
        pending = []
        if not args.real_local_test:
            submit = patch.object(assessment_api, "_submit", side_effect=lambda run_id, lease: pending.append((run_id, lease)))
            ready = patch.object(assessment_api, "prepared", return_value=True)
            submit.start()
            ready.start()
            progress_directory = patch("app.assurance_progress.DIRECTORY", folder / "progress")
            progress_directory.start()
        server = uvicorn.Server(uvicorn.Config("app.pilot:app", host="127.0.0.1", port=port,
                                               lifespan="off", log_level="warning"))
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        try:
            for _ in range(240):
                if server.started:
                    break
                time.sleep(.2)
            else:
                raise RuntimeError("Isolated UI server did not start")
            from app import lab_policy
            fixture_lab_url = 'http://127.0.0.1:9876/api/v1/workspace/qa/chat'
            lab_policy.configure_local_targets(lab_policy.configured_local_targets() + [fixture_lab_url])
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                page = browser.new_page(viewport={"width": 1440, "height": 1000})
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.goto(url + "/", wait_until="networkidle", timeout=60000)
                assert page.locator('#landing-nav > button:visible').all_text_contents() == ['Home', 'Demo', 'Reports', 'Account']
                page.locator('#nav-interactive-demo').click()
                assert page.locator('#nav-interactive-demo').get_attribute('aria-current') == 'page'
                assert page.locator('#nav-demo').get_attribute('aria-current') is None
                page.locator('#nav-demo').click()
                assert page.locator('.hero-product').evaluate('(element) => getComputedStyle(element).transform') == 'none'
                page.locator('#hero-report').click()
                page.locator("#page-assessments").wait_for(state="visible")
                assert page.locator('#demo-scan-run').is_disabled()
                assert page.locator("#repair-demo").is_visible()
                assert page.locator("#technical-lab").is_hidden()
                held_demo_requests = []
                page.route('**/demo/repair-example**', lambda route: held_demo_requests.append(route))
                with page.expect_request('**/demo/repair-example**'):
                    page.locator("#repair-start").click()
                page.locator('.demo-loading progress').wait_for(state='visible')
                assert page.locator('.demo-loading progress').get_attribute('value') is None
                assert page.locator('#repair-start').is_disabled()
                assert len(held_demo_requests) == 1
                held_demo_requests[0].continue_()
                page.unroute('**/demo/repair-example**')
                page.get_by_text("Unauthorised disclosure in the example", exact=True).wait_for()
                assert "CONFIDENTIAL TEST DOCUMENT" in page.locator("#repair-evidence").inner_text()
                assert "Attack blocked:" not in page.locator("#repair-evidence").inner_text()
                assert page.locator('.first-report-metrics').is_visible()
                page.locator("#repair-evidence summary").click()
                assert '+    if user["organisation_id"]' in page.locator("#repair-evidence").inner_text()
                page.locator("#repair-next").click()
                page.locator('.demo-loading progress').wait_for(state='visible')
                page.get_by_text("Attack blocked: the other company’s document was not returned.", exact=True).wait_for()
                assert "Normal use passed:" in page.locator("#repair-evidence").inner_text()
                assert page.locator('.demo-result-stat').count() == 3
                assert page.locator('.fix-comparison .comparison-card').count() == 2
                assert page.locator("#repair-next").is_hidden()
                for width in (390, 768, 1440):
                    page.set_viewport_size({"width": width, "height": 1000})
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), width
                customer_screenshots = ROOT / '.venv/ui-preview'
                customer_screenshots.mkdir(parents=True, exist_ok=True)
                page.screenshot(path=str(customer_screenshots / 'find-and-fix.png'), full_page=True)
                page.locator("#repair-reset").click()
                assert page.locator("#repair-start").is_visible()
                assert "CONFIDENTIAL TEST DOCUMENT" not in page.locator("#repair-evidence").inner_text()
                page.locator('#nav-demo').click()
                for width in (390, 768, 1440):
                    page.set_viewport_size({'width': width, 'height': 1000})
                    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), width
                    page.screenshot(path=str(customer_screenshots / f'overview-{width}.png'), full_page=True)
                page.locator('#nav-checks').click()
                page.get_by_text('Your first check starts here.', exact=True).wait_for()
                page.go_back()
                page.locator('#page-demo').wait_for(state='visible')
                page.go_forward()
                page.locator('#page-checks').wait_for(state='visible')
                page.locator('#checks-new').click()
                assert page.locator('#connect-step-1').is_visible()
                assert page.locator('#connect-step-2').is_hidden()
                page.locator('#connection-next').click()
                assert 'Add your AI connection' in page.locator('#connection-step-error').inner_text()
                page.locator('#use-local-application').click()
                assert page.locator('#target-input').input_value() == fixture_lab_url
                page.locator('#connection-next').click()
                assert page.locator('#http-token').is_visible()
                assert page.locator('.verification').is_hidden()
                assert page.locator('#http-response-path').input_value() == 'textResponse'
                page.locator('#connection-next').click()
                assert page.locator('#connect-step-3').is_visible()
                page.locator('#connection-back').click()
                page.locator('#connection-back').click()
                page.locator('#choose-model').click()
                page.locator('#target-input').fill('gpt-example')
                page.locator('#connection-next').click()
                assert page.locator('#connect-step-2').is_visible()
                page.locator('#connection-next').click()
                assert 'test API key' in page.locator('#connection-step-error').inner_text()
                page.locator('#api-key').fill('synthetic-key-never-sent-to-a-provider')
                page.locator('#connection-back').click()
                page.locator('#target-input').fill('gpt-another-example')
                assert page.locator('#api-key').input_value() == ''
                assert not page.locator('#agree').is_checked()
                page.locator('#connection-next').click()
                page.locator('#api-key').fill('synthetic-key-never-sent-to-a-provider')
                page.locator('#connection-next').click()
                assert page.locator('#connect-step-3').is_visible()
                assert page.locator('#go').is_disabled()
                page.locator('#connection-back').click()
                assert page.locator('#connect-step-2').is_visible()
                page.locator('#api-key').fill('')
                # Calendar benchmark remains an explicit internal development view.
                page.goto(url + "/?lab=1#assessments", wait_until="networkidle")
                page.locator("#technical-lab > summary").click()
                page.locator("#benchmark-result .benchmark-outcome").wait_for()
                assert page.locator("#benchmark-result .benchmark-outcome").inner_text() == "Attack goal not observed"
                assert page.locator("#benchmark-result .benchmark-checks li").count() == 3
                assert page.locator("#page-back").inner_text() == "Back: What we test"
                assert page.locator("#page-next").inner_text() == "Next: Test your AI"
                page.locator("#page-next").click()
                assert page.locator("#view-start").is_visible()
                assert page.locator("#scan-profile").input_value() == "free"
                page.locator("#use-example-endpoint").click()
                assert page.locator("#scan-profile").input_value() == "full"
                assert page.locator("#scan-profile").is_disabled()
                assert "five attack categories" in page.locator("#scan-scope-note").text_content()
                page.locator("#target-input").fill("gpt-example")
                assert page.locator("#scan-profile").input_value() == "free"
                assert page.locator("#scan-profile").is_enabled()
                assert "prompt injection only" in page.locator("#scan-scope-note").text_content()
                page.locator("#page-back").click()
                assert page.locator("#page-assessments").is_visible()
                page.locator('#nav-account').click()
                page.locator("#account-open").click()
                page.locator("#account-toggle").click()
                page.locator("#nav-assessments").click()
                assert page.locator("#account-panel").is_hidden()
                screenshots = ROOT / ".venv/ui-preview"
                screenshots.mkdir(parents=True, exist_ok=True)
                for width in (390, 768, 1440):
                    page.set_viewport_size({"width": width, "height": 1000})
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), width
                    if width in (390, 1440):
                        page.screenshot(path=str(screenshots / f"assessments-{width}.png"), full_page=True)
                assert page.locator("#benchmark-run").is_disabled()
                credit = page.request.get(url + "/account/session").json()["free_scan_available"]
                page.locator("#benchmark-agree").check()
                page.locator("#benchmark-run").click()
                page.wait_for_function("() => document.getElementById('benchmark-status').textContent.includes('Local test started')", timeout=30000)
                assert page.locator("#benchmark-run").is_disabled()
                page.locator("#nav-plans").click()
                page.locator("#nav-assessments").click()
                assert page.locator("#benchmark-source").inner_text() == "Your local test is running"
                page.reload(wait_until="networkidle")
                page.wait_for_function("() => document.querySelectorAll('.benchmark-live-stages li').length===5")
                assert page.locator("#benchmark-source").inner_text() == "Your local test is running"
                if not args.real_local_test:
                    assert len(pending) == 1
                    run_id, lease = pending[0]
                    from app.assurance_progress import publish
                    publish(run_id, "attacked", completed=("clean_user", "goal_capability"), requests=4, tools=2)
                    page.wait_for_function("() => document.querySelector('.benchmark-live-stages li.active')?.textContent.includes('Add a hidden instruction')")
                    fixture = copy.deepcopy(assessment_api.REFERENCE)
                    fixture["source"] = "synthetic_ui_test_fixture"
                    assessment_api._finish(run_id, "complete", fixture)
                    lease.close()
                print("Waiting for " + ("actual local model" if args.real_local_test else "UI fixture") + " result.", flush=True)
                page.wait_for_function("() => document.getElementById('benchmark-source').textContent==='Your local-model benchmark'", timeout=480000)
                assert page.locator("#benchmark-result .benchmark-outcome").inner_text() in ("Inconclusive", "Attack goal observed", "Attack goal not observed")
                assert page.locator(".benchmark-explanation").inner_text()
                assert page.request.get(url + "/account/session").json()["free_scan_available"] == credit
                page.locator("#benchmark-recorded").click()
                assert "Recorded" in page.locator("#benchmark-source").text_content()
                page.locator("#benchmark-latest").click()
                assert page.locator("#benchmark-source").inner_text() == "Your local-model benchmark"
                result = page.request.get(url + "/account/assurance/runs/latest").json()
                assert result["status"] == "complete", result
                print("Final assessment:", result["result"]["assessment"], flush=True)
                # Signup preserves the guest's result; logout removes private UI state.
                page.locator('#nav-account').click()
                page.locator("#account-open").click()
                page.locator("#account-toggle").click()
                page.locator("#account-email").fill("assessment-qa-" + uuid4().hex[:10] + "@example.com")
                page.locator("#account-password").fill("qa-only-password-123456")
                page.locator("#account-submit").click()
                page.locator("#logout").wait_for(state="visible")
                page.locator("#logout").click()
                page.locator('#page-demo').wait_for(state='visible')
                page.locator('#nav-account').click()
                page.locator("#account-open").wait_for(state="visible")
                assert page.locator('#verification-token').text_content() == ''
                assert page.locator('#target-input').input_value() == ''
                assert not page.locator('#agree').is_checked()
                page.locator("#nav-assessments").click()
                assert page.locator("#benchmark-latest").is_hidden()
                assert "Recorded" in page.locator("#benchmark-source").text_content()
                page.locator('#nav-interactive-demo').click()
                page.locator('.extra-demo-scan > summary').click()
                before_demo_credit = page.request.get(url + '/account/session').json()['free_scan_available']
                page.locator('#demo-scan-agree').check()
                with page.expect_response(lambda response: response.url == url + '/scan' and response.request.method == 'POST') as demo_started:
                    page.locator('#demo-scan-run').click()
                assert demo_started.value.status == 202, demo_started.value.text()
                demo_id = demo_started.value.json()['scan_id']
                print('Running actual garak demo pipeline:', demo_id, flush=True)
                page.wait_for_function("() => document.querySelector('#main .report-head') !== null || !document.getElementById('view-failed').classList.contains('hidden')", timeout=240000)
                assert page.locator('#view-failed').is_hidden(), page.locator('#failed-msg').text_content()
                assert page.locator('#main .report-head').is_visible()
                assert page.request.get(url + '/account/session').json()['free_scan_available'] == before_demo_credit
                actual_report = page.request.get(url + '/scan/' + demo_id + '/report').json()
                assert actual_report['scan_profile'] == 'full'
                assert len(actual_report['categories']) == 5
                print('PASS: real demo scan produced five-category report without consuming the free customer scan.', flush=True)
                os.environ["ARISEC_LOCAL_ASSURANCE"] = "0"
                page.goto(url + "/?lab=1#assessments", wait_until="networkidle")
                page.locator("#nav-assessments").click()
                page.locator("#technical-lab > summary").click()
                page.locator("#benchmark-result .benchmark-outcome").wait_for()
                assert page.locator("#local-benchmark-controls").is_hidden()
                assert "not available on this deployment" in page.locator("#benchmark-availability").inner_text()
                assert not errors, errors
                browser.close()
                print("PASS: assessment navigation, consent, owner session, progress, result switching, credit preservation, logout and responsive layout.", flush=True)
        finally:
            assessment_api._shutdown()
            server.should_exit = True
            thread.join(timeout=15)
            for _, lease in pending:
                lease.close()
            if not args.real_local_test:
                submit.stop()
                ready.stop()
                progress_directory.stop()
            if thread.is_alive():
                raise RuntimeError("Isolated server did not stop")


if __name__ == "__main__":
    main()
