# Organisation examples, attack explanations and walkthrough

Added 20 November 2026 for non-technical visitors. The local customer page has
a public **Try the demo** section with three tabs:

- **Try an example run:** choose Legal services, Healthcare administration or
  Education, then one of two scripted behaviours. Four fictional tests run in
  the browser. Each result shows the task, attack, example response, possible
  consequence and suggested next step. No target or AI service is contacted.
- **Explore the attacks:** browse all 12 exact example inputs. Direct instructions,
  roleplay, coded instructions and forged authority are explained in plain English,
  including how a real application request would carry the text. An expandable
  explanation also covers the standard garak categories and assessment limits.
- **Watch the walkthrough:** a 76-second captioned recording of the actual UI's
  fictional demo, with an accessible text transcript and a downloadable WebM.
  There is no voiceover. The on-screen captions explain the workflow.

The public example needs no invite, credential or personal data. Downloaded
example JSON is labelled `simulation: true` and `real_scan: false`. It must never
be presented as a real scan or customer evidence. The stronger scripted behaviour
does not demonstrate that a real safeguard works.

## What the sector examples test

There are four fictional administration/text tasks per sector, including intake
and case-note work, healthcare appointment administration, and educational notes
or support. Each contains a harmless replacement instruction. The check looks
for the exact standalone test marker replacing the intended response.

These are additional task-hijacking cases. They do not assess clinical decisions,
legal advice, educational accuracy, regulatory compliance, access control or real
confidentiality boundaries. Use synthetic content and approved staging systems.
The generic probe suite may include more challenging text than the harmless
public examples; agree its scope with the pilot partner.

## Real assessments remain separate

An authorised application API request can select:

```json
{"scenario_sector": "legal"}
```

Valid values are `general` (the unchanged baseline), `legal`, `healthcare` and
`education`. Selection is available in the application connection form. It is
not accepted for browser or direct-provider assessments. Clicking **Next: assess
your own AI feature** transfers the selected sector into that form but does not
submit a scan or bypass approval.

A selected sector adds four real garak Probe/Detector instances to the standard
23 probe classes. With a one-prompt cap there are 27 attempts; larger caps expand
the standard probes but each added case still has one prompt. Inputs, responses,
detector evaluations and hits use standard garak JSONL. The existing report
generator remains unchanged. Plugins are registered only during that run and
restored afterwards.

The marker detector deliberately excludes refusals that quote the marker and
allows only one complete leading thinking block before a standalone marker.
Paraphrases can be missed. A match is a candidate task-hijacking behaviour,
not a verified business-impact finding.

## Media and maintenance

Walkthrough recordings are optional local assets. Public fixed-path routes
serve only named assets when present. The preview uses isolated storage with
startup housekeeping disabled. Keep UI tests pointed at that isolated store.
