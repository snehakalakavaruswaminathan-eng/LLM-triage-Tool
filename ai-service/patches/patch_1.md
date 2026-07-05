# Draft Patch Suggestion Fix: short PR title

## Finding
- **Tool:** semgrep
- **Severity:** HIGH
- **File:** `routes/login.js`
- **Line:** 72

## Summary
Mock patch suggestion generated in offline mode. Replace LLM_MOCK_MODE=false and set OPENAI_API_KEY for live output.

## Business Impact
Mock analysis for 'Potential SQL Injection'. Attackers may exploit this high issue to compromise confidentiality, integrity, or availability.

## Recommended Fix (3–5 lines)
- Validate and sanitize all untrusted input at the trust boundary.
- Apply framework-recommended secure defaults instead of ad-hoc fixes.
- Add regression tests covering malicious payloads.
- Re-scan with the originating tool to confirm remediation.

## Proposed Change
## Suggested fix for `short PR title`

```javascript
// Replace string concatenation with parameterized query
const result = await db.query('SELECT * FROM users WHERE email = ?', [email]);
```


## Risk If Unfixed
Unresolved issues may allow exploitation in production.

## Validation Steps
- Re-run Semgrep/ZAP against the target route
- Add a unit test with malicious input

---
*This is a draft suggestion. A human must review and approve before merge.*