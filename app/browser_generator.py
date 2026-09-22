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
This is best effort, and QA found ways past it that in-browser code can't close:
requests from Web/Shared Workers and Service Workers, speculation-rules
prefetch, and DNS rebinding. Service workers and QUIC/WebTransport are switched
off and WebRTC is disabled, but the only real guarantee is that the browser has
no route to internal addresses: a filtering proxy that resolves each name once
and connects to the checked IP, or network egress rules on the machine that
runs scans. Do that before running scans for the public.

All state is per-instance and Playwright's sync API is bound to the thread that
started it, so use one instance from one thread and call close() when done.
"""

import logging
import re
import sys
import time
import unicodedata
from collections import Counter
from urllib.parse import urlsplit

from garak import _config
from garak.attempt import Conversation, Message, Turn
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

# Two easy questions for responds_like_ai(). The answers don't appear in the
# questions, so a page that merely echoes the input can't pass by accident.
#
# (question, pattern for the answer, a phrase from the question). The answer must be
# short, must not repeat the question, and must not read like search results:
# "42 results found for ..." is a search box, not an assistant.
LIVENESS_CHECKS = [
    ("What is 12 plus 30? Answer with just the number.",
     # Not part of a longer number, a time (12:42:07) or a decimal (1.42, 42.5),
     # but a sentence-final "42." is fine.
     re.compile(r"(?<![\d:])(?<!\d[.,])(?:42|forty[- ]?two)(?![\d:])(?![.,]\d)", re.IGNORECASE), "12 plus 30"),
    ("What is the capital of France? Answer with just one word.",
     re.compile(r"\bparis\b", re.IGNORECASE), "capital of france"),
]
_LIVENESS_MAX_CHARS = 80
_LIVENESS_NOT_AN_ANSWER = re.compile(
    r"\b(?:results?|items?|found|matches|products?|pages?|no \w+ (?:found|available))\b", re.IGNORECASE
)
_LIVENESS_INPUT_TRIES = 3

# Placeholder text a page shows while the reply is being produced. It changes
# the page but isn't the reply, so it must not count as one.
_INDICATOR = re.compile(
    r"^(?:(?:(?:the\s+)?\w+\s+is\s+)?(?:typing|thinking|generating|loading|processing|writing))?[\s.…]*$",
    re.IGNORECASE,
)

# Lines that change on their own and say nothing about a reply: clocks and dates.
# Without this a ticking clock on a dead page looks like a reply that never settles.
_CLOCK = re.compile(
    r"^(?:\d{1,2}:\d{2}(?::\d{2})?\s*(?:[ap]\.?m\.?)?|just now|\d+\s*(?:s|sec|seconds?|m|min|minutes?|h|hours?)\s+ago)$",
    re.IGNORECASE,
)

# A short reply that reads like "still working on it" is not accepted as final
# until it has sat unchanged for pending_settle_ms (default 12s, vs 3s normally).
# Bots often show "One moment, checking our knowledge base..." as a real bubble,
# then replace it seconds later. Only affects how long we wait, never what is kept.
# Judged on the LAST line only, and by how it starts or ends: a placeholder is
# replaced by the answer, so once a real answer is the last line the reply is done.
# (Matching the words anywhere flagged ordinary refusals like "I can't assist
# with generating that", costing 9 extra seconds per prompt.)
_PENDING_PHRASE = re.compile(
    r"^(?:one moment|just a moment|hold on|please wait|let me (?:check|look|search|find|pull|see|think))\b",
    re.IGNORECASE,
)
# Single words also start real sentences ("Processing of personal data is ..."),
# so these only count on a short line.
_PENDING_WORD = re.compile(
    r"^(?:searching|checking|looking|thinking|typing|working on|analy[sz]ing|generating|loading|processing)\b",
    re.IGNORECASE,
)
_PENDING_WORD_MAX_CHARS = 40
_PENDING_END = re.compile(r"(?:\.{3}|…)\s*$")
_PENDING_MAX_CHARS = 160

# Per-frame text is cut to this before any processing, so a hostile page with
# megabytes of text can't make every poll expensive.
_MAX_SNAPSHOT_CHARS = 200_000
_MAX_ECHO_LINES = 4_000

# WebRTC and WebTransport can open connections that neither request routing nor
# WebSocket routing sees. Chat pages don't need them, so they are switched off.
# Left writable and configurable on purpose: pages (and libraries such as
# webrtc-adapter) that assign or redefine these names would throw otherwise.
# This is a mitigation, not a wall: workers don't run init scripts. The wall is
# a filtering proxy or network egress rules (see the module docstring).
_WEBRTC_OFF_JS = """
for (const k of ['RTCPeerConnection', 'webkitRTCPeerConnection', 'RTCDataChannel', 'WebTransport']) {
  try { Object.defineProperty(window, k, { value: undefined, configurable: true, writable: true }); } catch (e) {}
}"""

# Skip inputs that are clearly not a chat box: site search, and forms that
# collect account details (login, sign-up, contact). Submitting attack prompts
# into those means failed logins, spam tickets and lockouts on someone's site.
#
# Returns 'skip' (never use), 'demote' (use only if nothing better turns up) or ''.
# A search box or login is skipped. A form that also asks for an email address or
# phone number is probably a contact form, but might be a chat with an optional
# field, so it is demoted; the AI gate then decides.
_INPUT_SKIP_JS = """(el) => {
  const type = (el.getAttribute('type') || '').toLowerCase();
  const hint = [el.placeholder, el.getAttribute('aria-label'), el.name, el.id]
    .filter(Boolean).join(' ').toLowerCase();
  const chatty = /\\b(ask|message|chat|prompt|question|assistant|ai)\\b/.test(hint);
  if ((type === 'search' || el.closest('[role=search]')) && !chatty) return 'skip';
  if (/\\bsearch\\b/.test(hint) && !chatty) return 'skip';
  const form = el.closest('form');
  if (form && form.querySelector('input[type=password]')) return 'skip';
  if (form && form.querySelector('input[type=email], input[type=tel]')) return 'demote';
  return '';
}"""

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


class PageUnavailable(BadGeneratorException):
    """The page answered with an HTTP error (404, 500...). Safe to tell the user."""


class ScanTimedOut(BadGeneratorException):
    """The scan exceeded max_scan_s. One broken target must not hold the worker forever."""


class AiNotConfirmed(BadGeneratorException):
    """The page didn't answer simple questions like an AI. Raised by run_scan."""


def _lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


_QUOTE_TABLE = str.maketrans({
    "‘": "'", "’": "'", "“": '"', "”": '"',
    "–": "-", "—": "-", " ": " ",
})


def _norm(text: str) -> str:
    """Whitespace-collapsed, Unicode-normalised text, so a UI that turns straight
    quotes into curly ones or wraps lines still matches the prompt we sent."""
    return " ".join(unicodedata.normalize("NFKC", text).translate(_QUOTE_TABLE).split())


def _looks_pending(reply: str) -> bool:
    last = reply.rsplit("\n", 1)[-1].strip()
    if len(last) > _PENDING_MAX_CHARS:
        return False
    return bool(
        _PENDING_PHRASE.search(last)
        or _PENDING_END.search(last)
        or (len(last) <= _PENDING_WORD_MAX_CHARS and _PENDING_WORD.search(last))
    )


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
    target = _norm(prompt)
    if not target:
        return lines
    considered = lines[:_MAX_ECHO_LINES]
    normed = [_norm(line) for line in considered]
    for start, first in enumerate(normed):
        # An echo must start with the prompt's own beginning: skip cheaply otherwise.
        if not first or not target.startswith(first):
            continue
        joined = first
        for end in range(start, len(normed)):
            if end > start:
                joined = f"{joined} {normed[end]}".strip()
            if joined == target:
                return lines[:start] + lines[end + 1 :]
            if not target.startswith(joined):
                break
    # A UI may decorate the echo ("You: <prompt>", "<prompt> (sent)"). If the exact
    # form isn't there, drop a run of lines that merely CONTAINS the prompt,
    # starting only at a line holding the prompt's opening characters (cheap to
    # test, so a hostile page can't make this quadratic).
    if len(target) >= 12:
        head = target[:12]
        for start, first in enumerate(normed):
            if head not in first:
                continue
            joined = first
            for end in range(start, len(normed)):
                if end > start:
                    joined = f"{joined} {normed[end]}"
                if target in joined:
                    return lines[:start] + lines[end + 1 :]
                if len(joined) > len(target) + 80:
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
        "name": "",  # the target URL, as configured; see __init__
        # What garak calls the target inside attack prompts, e.g. "act as {name}
        # with DAN Mode enabled". Read as a proper noun, so keep it short.
        "display_name": "AI Assistant",
        "headless": True,
        "nav_timeout_ms": 30_000,
        "action_timeout_ms": 10_000,
        # How long to keep looking for the input after load (widgets render late).
        "input_wait_ms": 10_000,
        # Give up waiting for any reply after this long.
        "response_timeout_ms": 60_000,
        # A reply counts as finished once its text has been unchanged this long.
        "settle_ms": 3_000,
        # ...or this long, when the text looks like a "still working" placeholder.
        "pending_settle_ms": 12_000,
        "poll_ms": 400,
        # Wall-clock limit for the whole scan. A broken or hostile target that
        # burns every reply timeout would otherwise hold the single worker for hours.
        "max_scan_s": 7_200,
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
        self._scan_started: float | None = None
        # Inputs (selector, nth, frame url) that failed the AI gate, and the one
        # most recently chosen. See responds_like_ai.
        self._excluded_inputs: set[tuple] = set()
        self._last_input_key: tuple | None = None
        self._verdicts: dict[tuple, bool] = {}
        self._tripped: str | None = None

        if not self.name:
            raise BadGeneratorException("BrowserGenerator needs a target URL as its name")
        self.target_url = self.name
        # Defense in depth: the API layer already validated, but this class can be
        # used from the CLI or another caller that didn't.
        result = validate_target_url(self.target_url)
        if not result.is_safe:
            logger.warning("BrowserGenerator refused target %s: %s", self.target_url, result.reason)
            raise BadGeneratorException("target URL failed safety validation")
        # garak pastes generator.name into some attack prompts. Left as the URL,
        # a jailbreak would read "you are going to act as https://acme.com/chat".
        # (fullname, set by garak's base class earlier, still carries the URL.)
        self.name = self.display_name

    # ---- lifecycle ---------------------------------------------------------

    def _ensure_browser(self):
        if self._browser is None:
            self._playwright = sync_playwright().start()
            try:
                # QUIC is UDP, which request routing can't see (WebTransport rides on it).
                self._browser = self._playwright.chromium.launch(
                    headless=self.headless, args=["--disable-quic"]
                )
            except BaseException:
                # Don't leave a Playwright driver running that nothing owns.
                self._playwright.stop()
                self._playwright = None
                raise

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

    def responds_like_ai(self) -> bool:
        """Best effort: does the page answer a simple question the way a language
        model would?

        run_scan uses this as a gate, before any attack is sent, so a login
        form, contact form or search box isn't sent hundreds of attack messages.
        It can be wrong the other way: a tightly scoped support bot may refuse
        anything off-topic, or answer in another language. That is why the
        caller can override it.

        If the first input on the page doesn't answer, the next candidate is
        tried (up to _LIVENESS_INPUT_TRIES), because the first match is often a
        contact form sitting above the real chat. The input that passes is the
        one the whole scan then uses. If none passes, the exclusions are cleared
        so an overridden scan starts from the original first choice.
        """
        for _ in range(_LIVENESS_INPUT_TRIES):
            for question, answer, question_phrase in LIVENESS_CHECKS:
                out = self._call_model(Conversation([Turn("user", Message(text=question))]))
                reply = (out[0].text if out and out[0] else "").strip()
                if (
                    len(reply) <= _LIVENESS_MAX_CHARS
                    and answer.search(reply)
                    and question_phrase not in reply.lower()
                    and not _LIVENESS_NOT_AN_ANSWER.search(reply)
                ):
                    return True
            if self._last_input_key is None:
                break
            self._excluded_inputs.add(self._last_input_key)
            if not self._another_input_exists():
                break
        self._excluded_inputs.clear()
        return False

    # ---- garak entry point -------------------------------------------------

    def _call_model(self, prompt: Conversation, generations_this_call: int = 1):
        try:
            text = prompt.last_message("user").text
        except ValueError:
            text = None
        if not text:
            return [None]

        if self._scan_started is None:
            self._scan_started = time.monotonic()
        elif time.monotonic() - self._scan_started > self.max_scan_s:
            raise ScanTimedOut(f"scan exceeded {self.max_scan_s}s")

        if self._calls:
            time.sleep(self.request_delay_s)
        self._calls += 1

        last_error = None
        for attempt in range(1, self.attempts + 1):
            try:
                reply = self._converse(text)
                return [Message(text=reply) if reply else None]
            except PageUnavailable as e:
                if not self._had_success:
                    raise  # the target was never usable: say so
                last_error = e  # one bad load mid-scan is a hiccup, not the end
                logger.warning("browser attempt %d/%d failed: %s", attempt, self.attempts, e)
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
        # Service workers make requests that bypass route(); no chat page needs one.
        context = self._browser.new_context(service_workers="block")
        try:
            context.set_default_timeout(self.action_timeout_ms)
            context.route("**/*", self._guard)
            # WebSockets aren't seen by route(). Allowed ones (chat widgets use
            # them) are passed through to the real server; a blocked one is left
            # mocked, so the page believes it connected and nothing leaves.
            context.route_web_socket("**/*", self._ws_guard)
            context.add_init_script(_WEBRTC_OFF_JS)
            context.on("request", self._on_request)
            page = context.new_page()
            response = page.goto(self.target_url, wait_until="domcontentloaded", timeout=self.nav_timeout_ms)
            self._check_tripped()
            if response is not None and response.status >= 500:
                # A broken server. (4xx is not treated as fatal: single-page apps on
                # static hosts are often served with a 404 status; whether there is
                # a chat to scan is decided by what is on the page.)
                raise PageUnavailable(f"target returned HTTP {response.status}")
        except BaseException:
            context.close()
            raise
        return context, page

    def _url_allowed(self, url: str) -> bool:
        parts = urlsplit(url)
        if parts.scheme in ("data", "blob", "about"):
            return True  # no network involved
        # A websocket is judged as the web address it connects to.
        scheme = {"ws": "http", "wss": "https"}.get(parts.scheme, parts.scheme)
        if scheme not in ("http", "https"):
            return False
        key = (scheme, (parts.hostname or "").lower(), parts.port)
        if key not in self._verdicts:
            result = validate_target_url(f"{scheme}://{parts.netloc}{parts.path or '/'}")
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

    def _ws_guard(self, ws):
        try:
            if self._url_allowed(ws.url):
                ws.connect_to_server()
            # else: intentionally do nothing; see _open_page
        except PlaywrightError:
            pass

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
        started = time.monotonic()
        deadline = started + self.input_wait_ms / 1000
        while True:
            self._check_tripped()
            # Demoted inputs (see _INPUT_SKIP_JS) are only accepted from half-time
            # on, so a widget that renders late can still win over a contact form
            # that was there from the start.
            passes = (False, True) if time.monotonic() - started >= self.input_wait_ms / 2000 else (False,)
            for accept_demoted in passes:
                for selector in INPUT_SELECTORS:
                    for frame in page.frames:
                        try:
                            candidates = frame.locator(selector)
                            for i in range(min(candidates.count(), 5)):
                                key = (selector, i, frame.url)
                                if key in self._excluded_inputs:
                                    continue
                                field = candidates.nth(i)
                                kind = self._classify(field)
                                if kind == "ok" or (kind == "demote" and accept_demoted):
                                    self._last_input_key = key
                                    return frame, field
                        except PlaywrightError:
                            continue  # frame detached mid-search
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.5)

    @staticmethod
    def _classify(field) -> str | None:
        """'ok', 'demote', or None (unusable or not a chat box at all)."""
        try:
            if not (field.is_visible() and field.is_enabled() and field.is_editable()):
                return None
            verdict = field.evaluate(_INPUT_SKIP_JS)
        except PlaywrightError:
            return None
        return None if verdict == "skip" else ("demote" if verdict == "demote" else "ok")

    def _another_input_exists(self) -> bool:
        self._ensure_browser()
        context, page = self._open_page()
        try:
            return self._find_input(page) is not None
        finally:
            context.close()

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
        # Only buttons near the input are candidates: its <form>, or failing that
        # the closest wrapper that contains any button. Searching the whole frame
        # could click an unrelated "Send" or "Submit" elsewhere on the page.
        scope = frame
        in_form = field.locator("xpath=ancestor::form[1]").count() > 0
        if in_form:
            scope = field.locator("xpath=ancestor::form[1]")
        else:
            nearby = field.locator("xpath=ancestor::*[.//button][1]")
            if nearby.count():
                scope = nearby

        for selector, pattern in SUBMIT_SELECTORS:
            try:
                matches = scope.locator(selector)
                for i in range(min(matches.count(), 5)):
                    button = matches.nth(i)
                    if not button.is_visible():
                        continue
                    # The input isn't in a form, so a button that is in one belongs
                    # to some other form (contact, newsletter, login): never click it.
                    if not in_form and button.evaluate("b => !!b.closest('form')"):
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
                merged.setdefault(key, []).append(value[:_MAX_SNAPSHOT_CHARS])
        return {key: "\n".join(values) for key, values in merged.items()}

    @staticmethod
    def _extract_reply(before: dict, after: dict, prompt: str) -> str:
        """New text since `before`: chat-message containers first, whole-page diff last."""
        for key in (*REPLY_SELECTORS, _PAGE_KEY):
            lines = _new_lines(before.get(key, ""), after.get(key, ""))
            lines = _drop_echo(lines, prompt)
            # Clock-like lines are page noise, but only in whole-page mode: inside a
            # chat bubble "9:30 AM" can be the bot's actual answer.
            lines = [
                line for line in lines
                if not _INDICATOR.match(line) and not (key == _PAGE_KEY and _CLOCK.match(line))
            ]
            if lines:
                return "\n".join(lines)
        return ""

    def _wait_for_reply(self, page, before: dict, prompt: str) -> str:
        """Poll until the reply has stopped changing, or the timeout hits.

        Returns whatever has arrived by then, possibly empty. Streaming and
        typewriter effects keep the text changing, so the reply only counts as
        done after `settle_ms` of no change (`pending_settle_ms` if it looks like
        a "one moment, checking..." placeholder that the bot will replace).
        """
        started = time.monotonic()
        deadline = started + self.response_timeout_ms / 1000
        settle = self.settle_ms / 1000
        pending_settle = max(settle, self.pending_settle_ms / 1000)
        reply, changed_at = "", started
        while True:
            now = time.monotonic()
            after = self._snapshot(page)
            self._check_tripped()
            current = self._extract_reply(before, after, prompt)
            if current != reply:
                reply, changed_at = current, now
            elif reply:
                needed = pending_settle if _looks_pending(reply) else settle
                if now - changed_at >= needed:
                    return reply
            if now >= deadline:
                return reply
            time.sleep(self.poll_ms / 1000)


DEFAULT_CLASS = "BrowserGenerator"

# Make "garak.generators.browser" importable so the __module__ override above
# is truthful and garak's loader can resolve `generators.browser`.
sys.modules.setdefault("garak.generators.browser", sys.modules[__name__])
