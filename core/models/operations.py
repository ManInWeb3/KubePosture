"""
Operational models — Phase 3+

Models:
- Report: generated PDF with SHA256 checksum (F12)
- ReportSchedule: cron-based auto-generation (F24)
- NotificationRule: condition -> channel dispatch (F21)
- ExceptionPolicy: auto-accept/acknowledge by pattern (F28)
- NamespaceGroup: namespace patterns -> team grouping (F27)

See: docs/architecture.md § Operational Features
"""
