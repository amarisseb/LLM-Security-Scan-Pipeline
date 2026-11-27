# Test an AI feature through its application API

Choose **Application API** in Arisec when you want requests to pass through the
application's own prompt, retrieval and controls. A model-provider baseline tests
the model directly and does not automatically exercise those application layers.

For a summarizer whose existing request is:

```json
{"document": "Text to summarize", "mode": "summary"}
```

use this request template:

```json
{"document": "{{prompt}}", "mode": "summary"}
```

If it returns `{"result": {"text": "The summary"}}`, enter `result.text` as
the response path. For an OpenAI-shaped response, use `choices.0.message.content`.
Each standalone `{{prompt}}` string value is replaced with the attack text.
String fragments, code expressions and custom headers are unsupported.

Provide an optional scoped bearer token. The token and template remain in memory
for the queued/running scan. Neither is written into scan status or garak config.
Treat templates as sensitive: use the token field for credentials, not JSON values.
The application itself can still record incoming requests in its logs.

## Connection limits

- Public HTTPS JSON POST endpoints, with certificate verification.
- The development launcher can register exact numeric loopback endpoints for a
  [local lab](local-lab.md). This exception is disabled by default.
- No redirects, URL credentials, query strings or fragments.
- Response path must identify a nonempty string in the JSON response.
- No streaming/SSE, file uploads, cookies, login flows, custom auth schemes,
  multi-step actions or arbitrary code-based transformations.
- All returned DNS addresses must be public. The chosen address is pinned for the
  request and TLS verifies the original hostname. Proxy environment is ignored.
- Responses are limited to 1 MB. DNS has a 5-second wait and each request has a
  30-second wall-clock socket deadline. Application scans stop between requests
  after 30 minutes. This is not an operating-system sandbox for probe code.

The component type is an organizational label. It does not yet select specialized
tests for document uploads, retrieval permissions or tool execution. A summarizer
receives attacks in the `document` field only when the supplied template maps it
there. Inspect the actual evidence before claiming an application vulnerability.

## Results and sharing

Each result includes the component name/type, connection mode, sent/unanswered
counts, attack evidence and recommendations. **Export report** downloads JSON,
including the raw garak report's SHA-256 and engine version. Candidate findings
need manual review; the score measures detector matches among evaluated attempts.

Results currently use unlisted scan links, not authenticated organizations. Keep
the local pilot private while account access and public browser egress are built.
