"""garak generator that drives a public chat web page instead of calling a model API.

For every probe prompt it opens a fresh browser context (so cookies, local
storage and chat history from earlier probes can't leak into this one), finds a
text input, types the prompt, submits it and reads back whatever the page
answered with.

Two page shapes are handled by the same code path:
  * chat thread: type into the box, press Enter (or click send), read the new bubble
  * one-shot tool: type into a field, click "Generate"/"Submit", read the output area

Third-party chat widgets (Intercom, Drift, Zendesk...) render inside iframes, so
every step looks through all frames of the page, not just the top-level DOM.

Every request the page makes is re-checked with url_safety:
  * a request straight to a non-public address is blocked before it is sent;
  * a redirect to one can't be blocked (Playwright doesn't route redirect hops),
    only detected. The scan is then aborted and nothing from that page is
    returned, but the browser has already sent that one request.
Neither covers DNS rebinding. The only hard guarantee against all of it is
network egress filtering on the machine that runs scans.

All state is per-instance and Playwright's sync API is bound to the thread that
started it, so use one instance from one thread and call close() when done.
"""

import logging
import re
import sys
import time
from collections import Counter
from urllib.parse import urlsplit

from garak import _config
from garak.attempt import Conversation, Message
from garak.exception import BadGeneratorException
from garak.generators.base import Generator
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

from .url_safety import validate_target_url

logger = logging.getLogger(__name__)

# Tried in this order across all frames, most specific first. A selector is tried
# in every frame before moving to the next one, so a precise match inside an
# iframe beats a vague match on the top-level page.
INPUT_SELECTORS = [
    "textarea[placeholder*='message' i]",
    "input[placeholder*='message' i]",
    "textarea[placeholder*='ask' i]",
    "input[placeholder*='ask' i]",
    "textarea[placeholder*='type' i]",
    "input[placeholder*='type' i]",
    "textarea[aria-label*='message' i]",
    "[contenteditable='true']",
    "[role='textbox']",
    "textarea",
    "input[type='text']",
    "input:not([type])",
]

# Elements whose new text is the bot's reply, most specific first. [role='log']
# and friends hold the whole transcript, so they come last and rely on echo
# removal to drop the user's own message.
REPLY_SELECTORS = [
    "[class*='bot-message' i]",
    "[class*='bot_message' i]",
    "[class*='botmessage' i]",
    "[class*='message-bot' i]",
    "[class*='assistant-message' i]",
    "[class*='ai-message' i]",
    "[data-message-author-role='assistant']",
    "[data-role='assistant']",
    "[role='log']",
]
_PAGE_KEY = "__page__"

# (selector, pattern). has-text() is a case-insensitive substring match, so
# "ask" would also click "Tasks" or "Basket"; the pattern rejects those.
SUBMIT_SELECTORS = [
    ("button:has-text('generate')", r"\bgenerate"),
    ("button:has-text('submit')", r"\bsubmit"),
    ("button:has-text('send')", r"\bsend"),
    ("button:has-text('ask')", r"\bask\b"),
    ("button[type='submit']", None),
]

# Placeholder text a page shows while the reply is being produced. It changes
# the page but isn't the reply, so it must not count as one.
_INDICATOR = re.compile(
    r"^(?:(?:(?:the\s+)?\w+\s+is\s+)?(?:typing|thinking|generating|loading|processing|writing))?[\s.…]*$",
    re.IGNORECASE,
)

# Collects, per frame and in one round trip: the text of every element matching
# each reply selector, and the text of the whole page. Looks inside open shadow
# roots, which some chat widgets use.
_SNAPSHOT_JS = """(selectors) => {
  const roots = [document];
  for (let i = 0; i < roots.length; i++)
    for (const el of roots[i].querySelectorAll('*'))
      if (el.shadowRoot) roots.push(el.shadowRoot);
  const text = (e) => e.innerText || '';
  const out = {};
  for (const s of selectors) {
    try {
      out[s] = roots.flatMap(r => Array.from(r.querySelectorAll(s)).map(text)).join('\\n');
    } catch (e) { out[s] = ''; }
  }
  out.__page__ = [document.body ? text(document.body) : '',
    ...roots.slice(1).flatMap(r => Array.from(r.children).map(text))].join('\\n');
  return out;
}"""


class _NoChatInput(Exception):
    """The page loaded but no usable text input was found in any frame."""


class ChatInputNotFound(BadGeneratorException):
    """No usable text input on the target page. Safe to tell the user about."""


class UnsafeRedirect(BadGeneratorException):
    """The page was redirected to a non-public address. Aborts the scan."""


def _lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def _new_lines(before: str, after: str) -> list[str]:
    """Lines in `after` that weren't in `before`, in order. Counts duplicates,
    so a repeated line only cancels as many times as it appeared before."""
    seen = Counter(_lines(before))
    fresh = []
    for line in _lines(after):
        if seen[line] > 0:
            seen[line] -= 1
        else:
            fresh.append(line)
    return fresh


def _drop_echo(lines: list[str], prompt: str) -> list[str]:
    """Remove the page's echo of the prompt we just sent, if it appears verbatim.

    Matches the whole prompt, not its parts: for an injection probe the correct
    "hijacked" reply is often a fragment of the prompt itself, and dropping every
    line that appears in the prompt would erase exactly the evidence we need.
    The echo may span several lines or be collapsed onto one, so whitespace is
    normalised and consecutive lines are joined before comparing.
    """
    target = " ".join(prompt.split())
    if not target:
        return lines
    for start in range(len(lines)):
        joined = ""
        for end in range(start, len(lines)):
            joined = f"{joined} {' '.join(lines[end].split())}".strip()
            if joined == target:
                return lines[:start] + lines[end + 1 :]
            if len(joined) >= len(target):
                break
    return lines


class BrowserGenerator(Generator):
    """Drive a public chat or one-shot generate web page with Playwright."""

    # garak namespaces plugin config by the last two parts of __module__
    # (generators.<name>). Left as app.browser_generator, that would resolve to
    # "app.browser_generator" and garak would silently ignore this plugin's
    # config, including the target name. Registered in sys.modules below so the
    # claimed module path is importable, which also lets garak's loader find it.
    __module__ = "garak.generators.browser"

    generator_family_name = "browser"
    active = True
    # One shared browser bound to one thread; garak's pool-based parallelism can't share it.
    parallel_capable = False
    supports_multiple_generations = False
    _unsafe_attributes = ["_playwright", "_browser"]

    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "name": "",  # the target URL
        "headless": True,
        "nav_timeout_ms": 30_000,
        "action_timeout_ms": 10_000,
        # How long to keep looking for the input after load (widgets render late).
        "input_wait_ms": 10_000,
        # Give up waiting for any reply after this long.
        "response_timeout_ms": 60_000,
        # A reply counts as finished once its text has been unchanged this long.
        "settle_ms": 3_000,
        "poll_ms": 400,
        # Pause between prompts so we don't hammer someone else's site.
        "request_delay_s": 1.0,
        "max_response_chars": 20_000,
        # Tries per prompt when the browser or page hiccups.
        "attempts": 2,
    }

    def __init__(self, name="", config_root=_config):
        # `name` is the target URL, from the argument or from garak config.
        super().__init__(name, config_root=config_root)
        self._playwright = None
        self._browser = None
        self._had_success = False
        self._calls = 0
        self._verdicts: dict[tuple, bool] = {}
        self._tripped: str | None = None

        if not self.name:
            raise BadGeneratorException("BrowserGenerator needs a target URL as its name")
        # Defense in depth: the API layer already validated, but this class can be
        # used from the CLI or another caller that didn't.
        result = validate_target_url(self.name)
        if not result.is_safe:
            logger.warning("BrowserGenerator refused target %s: %s", self.name, result.reason)
            raise BadGeneratorException("target URL failed safety validation")

    # ---- lifecycle ---------------------------------------------------------

    def _ensure_browser(self):
        if self._browser is None:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(headless=self.headless)

    def close(self):
        try:
            if self._browser is not None:
                self._browser.close()
        except PlaywrightError:
            logger.debug("error closing browser", exc_info=True)
        finally:
            if self._playwright is not None:
                self._playwright.stop()
            self._browser = self._playwright = None

    def preflight(self):
        """Load the target once and confirm a chat input exists.

        Raises BadGeneratorException if not, so a scan of a page with no chat
        surface fails in seconds instead of running every probe against nothing.
        """
        self._ensure_browser()
        context, page = self._open_page()
        try:
            if self._find_input(page) is None:
                raise ChatInputNotFound("no chat input found on the target page")
        finally:
            context.close()

    # ---- garak entry point -------------------------------------------------

    def _call_model(self, prompt: Conversation, generations_this_call: int = 1):
        try:
            text = prompt.last_message("user").text
        except ValueError:
            text = None
        if not text:
            return [None]

        if self._calls:
            time.sleep(self.request_delay_s)
        self._calls += 1

        last_error = None
        for attempt in range(1, self.attempts + 1):
            try:
                reply = self._converse(text)
                return [Message(text=reply) if reply else None]
            except (_NoChatInput, PlaywrightError) as e:
                last_error = e
                logger.warning("browser attempt %d/%d failed: %s", attempt, self.attempts, e)
        # Never got a single working exchange: the target isn't drivable, so say
        # so loudly rather than returning empty output for every probe.
        if isinstance(last_error, _NoChatInput) and not self._had_success:
            raise ChatInputNotFound("no chat input found on the target page")
        return [None]

    # ---- one prompt --------------------------------------------------------

    def _converse(self, prompt_text: str) -> str:
        self._ensure_browser()
        context, page = self._open_page()
        try:
            found = self._find_input(page)
            if found is None:
                raise _NoChatInput()
            frame, field = found

            self._type(page, field, prompt_text)
            # Snapshot after typing but before sending, so page changes caused
            # by typing itself (character counters, enabled buttons) aren't
            # mistaken for a reply.
            before = self._snapshot(page)
            self._submit(frame, field)
            self._had_success = True

            reply = self._wait_for_reply(page, before, prompt_text)
            self._check_tripped()
            return reply[: self.max_response_chars]
        finally:
            context.close()

    def _open_page(self):
        self._verdicts = {}
        self._tripped = None
        context = self._browser.new_context()
        try:
            context.set_default_timeout(self.action_timeout_ms)
            context.route("**/*", self._guard)
            context.on("request", self._on_request)
            page = context.new_page()
            page.goto(self.name, wait_until="domcontentloaded", timeout=self.nav_timeout_ms)
            self._check_tripped()
        except BaseException:
            context.close()
            raise
        return context, page

    def _url_allowed(self, url: str) -> bool:
        parts = urlsplit(url)
        if parts.scheme in ("data", "blob", "about"):
            return True  # no network involved
        if parts.scheme not in ("http", "https"):
            return False
        key = (parts.scheme, (parts.hostname or "").lower(), parts.port)
        if key not in self._verdicts:
            result = validate_target_url(url)
            self._verdicts[key] = result.is_safe
            if not result.is_safe:
                logger.warning("page tried to reach %s: %s", url, result.reason)
        return self._verdicts[key]

    def _guard(self, route):
        """Block any request the page makes to a non-public address."""
        try:
            if self._url_allowed(route.request.url):
                route.continue_()
            else:
                route.abort("blockedbyclient")
        except PlaywrightError:
            pass  # page or context already closing

    def _on_request(self, request):
        """Watch redirect hops, which _guard never sees. Can only flag them."""
        if request.redirected_from is not None and not self._url_allowed(request.url):
            self._tripped = request.url

    def _check_tripped(self):
        # Playwright delivers events while we call into it, so this is checked
        # after every step and before any page text is returned.
        if self._tripped:
            logger.error("scan aborted: page redirected to non-public address %s", self._tripped)
            raise UnsafeRedirect("page redirected to a non-public address")

    # ---- finding and driving the input ------------------------------------

    def _find_input(self, page):
        """Poll until a usable input shows up in any frame; (frame, locator) or None."""
        deadline = time.monotonic() + self.input_wait_ms / 1000
        while True:
            self._check_tripped()
            for selector in INPUT_SELECTORS:
                for frame in page.frames:
                    try:
                        candidates = frame.locator(selector)
                        for i in range(min(candidates.count(), 5)):
                            field = candidates.nth(i)
                            if self._is_usable(field):
                                return frame, field
                    except PlaywrightError:
                        continue  # frame detached mid-search
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.5)

    @staticmethod
    def _is_usable(field) -> bool:
        try:
            return field.is_visible() and field.is_enabled() and field.is_editable()
        except PlaywrightError:
            return False

    @staticmethod
    def _type(page, field, text):
        try:
            field.fill(text)
        except PlaywrightError:
            # Custom editors that aren't a real input/textarea/contenteditable.
            field.click()
            page.keyboard.insert_text(text)

    def _submit(self, frame, field):
        """Click an explicit submit button in the input's frame; otherwise press Enter."""
        button = self._find_submit(frame, field)
        if button is not None:
            try:
                button.click()
                return
            except PlaywrightError:
                logger.debug("submit click failed, falling back to Enter", exc_info=True)
        field.press("Enter")

    def _find_submit(self, frame, field):
        # If the input sits in a <form>, only that form's buttons are candidates:
        # a page can have a newsletter "Submit" next to the chat box.
        scope = frame
        form = field.locator("xpath=ancestor::form[1]")
        if form.count():
            scope = form

        for selector, pattern in SUBMIT_SELECTORS:
            try:
                matches = scope.locator(selector)
                for i in range(min(matches.count(), 5)):
                    button = matches.nth(i)
                    if not button.is_visible():
                        continue
                    if pattern:
                        label = f"{button.inner_text()} {button.get_attribute('aria-label') or ''}"
                        if not re.search(pattern, label, re.IGNORECASE):
                            continue
                    if self._wait_enabled(button):
                        return button
            except PlaywrightError:
                continue
        return None

    @staticmethod
    def _wait_enabled(button, timeout_s: float = 1.5) -> bool:
        # Send buttons are often disabled until the input has text.
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                if button.is_enabled():
                    return True
            except PlaywrightError:
                return False
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.1)

    # ---- reading the reply -------------------------------------------------

    def _snapshot(self, page) -> dict[str, str]:
        """Text per reply selector plus the whole page, merged across every frame."""
        merged: dict[str, list[str]] = {}
        for frame in page.frames:
            try:
                data = frame.evaluate(_SNAPSHOT_JS, REPLY_SELECTORS)
            except PlaywrightError:
                continue  # frame navigating or detached
            for key, value in data.items():
                merged.setdefault(key, []).append(value)
        return {key: "\n".join(values) for key, values in merged.items()}

    @staticmethod
    def _extract_reply(before: dict, after: dict, prompt: str) -> str:
        """New text since `before`: chat-message containers first, whole-page diff last."""
        for key in (*REPLY_SELECTORS, _PAGE_KEY):
            lines = _new_lines(before.get(key, ""), after.get(key, ""))
            lines = _drop_echo(lines, prompt)
            lines = [line for line in lines if not _INDICATOR.match(line)]
            if lines:
                return "\n".join(lines)
        return ""

    def _wait_for_reply(self, page, before: dict, prompt: str) -> str:
        """Poll until the reply has stopped changing, or the timeout hits.

        Returns whatever has arrived by then, possibly empty. Streaming and
        typewriter effects keep the text changing, so the reply only counts as
        done after `settle_ms` of no change.
        """
        started = time.monotonic()
        deadline = started + self.response_timeout_ms / 1000
        settle = self.settle_ms / 1000
        reply, changed_at = "", started
        while True:
            now = time.monotonic()
            after = self._snapshot(page)
            self._check_tripped()
            current = self._extract_reply(before, after, prompt)
            if current != reply:
                reply, changed_at = current, now
            elif reply and now - changed_at >= settle:
                return reply
            if now >= deadline:
                return reply
            time.sleep(self.poll_ms / 1000)


DEFAULT_CLASS = "BrowserGenerator"

# Make "garak.generators.browser" importable so the __module__ override above
# is truthful and garak's loader can resolve `generators.browser`.
sys.modules.setdefault("garak.generators.browser", sys.modules[__name__])
