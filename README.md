# claude-code-permissions-audit

A field-report methodology for auditing Claude Code permission
allow/deny lists. Written for the specific case where sandboxing
isn't an option and matcher-based `settings.json` rules are doing
the actual gating.

This is not a replacement for [Anthropic's official permissions
docs](https://code.claude.com/docs/en/permissions) — those are the
source of truth, and they're clear that matcher-based argument
constraints are fragile and that sandboxing plus PreToolUse hooks
are the primary defenses. This methodology is for environments
where those aren't available, or as a defense-in-depth layer on
top.

The doc walks through the iterative method, a catalog of nine gap
classes we surfaced across six audit rounds, matcher limits we
chose to document rather than chase, and example allow/deny lists
(72 entries / 66 entries) as illustration — not as recommended
defaults.

→ **[Read the methodology](./permissions-audit-methodology.md)**

License: [CC-BY 4.0](./LICENSE). Adapt freely with attribution.
