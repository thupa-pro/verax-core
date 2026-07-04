---
name: Compliance Violation Report
about: Auto-filed by the Compliance Bot when daily checks detect violations.
title: 'Compliance Bot: [critical/warning] violation detected — YYYY-MM-DD'
labels: compliance-bot, automated
assignees: ''
---

## Compliance Violation

This issue was **auto-generated** by the [Compliance Bot](https://github.com/{{ repository }}/actions/workflows/compliance-bot.yml) on {{ date | date('YYYY-MM-DD') }}.

### Check That Failed

<!-- One of: CBOR Library Audit / BLAKE3 Monitor / CT Log Key Rotation / Specification Diff / Cross-Implementation Interop -->

### Severity

<!-- Critical or Warning -->

### Details

```
(paste compliance bot output here)
```

### Required Action

- **Critical**: Immediate fix required. Assign SRE/security engineer.
- **Warning**: Review and either fix or acknowledge within 7 days.

### Check Previous Runs

- [Workflow history](https://github.com/{{ repository }}/actions/workflows/compliance-bot.yml)
- [Compliance report from this run](https://github.com/{{ repository }}/actions/runs/{{ env.GITHUB_RUN_ID }})

---

_This issue will be automatically closed when the check passes in a subsequent run._
