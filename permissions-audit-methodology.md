# Auditing Claude Code permission allow/deny lists

A field report from one team that ran six rounds of audit on a Claude Code
`settings.json` permission list. The method is for environments where
sandboxing isn't an option and matcher-based allow/deny is the primary
control. This is defense-in-depth, not a primary defense — the
[official permissions docs](https://code.claude.com/docs/en/permissions)
are clear about that, and so are we.

## When this guide applies

Use this method when:

- **Sandboxing is unavailable or insufficient** — CI, devcontainers,
  restricted hosts where OS-level enforcement isn't an option.
- **Matcher-based denial is the primary control** — your `settings.json`
  allow/deny rules are doing the actual gating.
- **An existing list grew organically** and hasn't been reviewed
  end-to-end.

The official permissions docs note matcher-based argument constraints are
fragile and recommend sandboxing plus PreToolUse hooks as the primary
defense. This guide assumes you've already considered those and either
can't use them or want a defense-in-depth layer on top. It complements
those defenses; it does not replace them.

If sandboxing is available in your environment, prefer it. If hooks are
an option, prefer them for the high-risk command classes. This method is
for the gap.

## The iterative method

A single pass surfaces the obvious destructive patterns. The interesting
gaps — argument-order variants, prefix-wildcard coverage, alternate-syntax
mutations — only surface on iteration.

The loop:

1. **Dump the current list** to a working scratchpad.
2. **Pick one gap class** from the catalog below and walk the deny list
   looking for it.
3. **Add anything missing.**
4. **Repeat with the next gap class.**

Stop when a pass produces no new findings.

Our run took six rounds and settled at **72 allows / 67 denies** for the
audited core (lists in the appendix). Round 1 was the initial draft —
roughly 68 allows / 33 denies. Most of the deny-list growth came on
rounds 2–6, which is the point: the method's value is what it surfaces
*after* the obvious pass.

Rule precedence is worth knowing: per the official docs, rules are
evaluated **deny → ask → allow**, first match wins. That's why this
method puts disproportionate attention on the deny list. Deny rules are
where matcher precision matters most.

## Gap classes to look for

These are the categories that surfaced on our six rounds. Each one
corresponds to at least one entry we missed on round 1 and only caught
later.

**1. Flag-order variants.** `rm -rf` and `rm -fr` are not the same
string. The matcher matches strings.

**2. Argument-order variants.** `git push --force origin main` and
`git push origin main --force` are not the same string either. The
`git push --force*` family in our deny list (12 entries) is what fell
out of taking this seriously: bare and `-C *` scopes, short and long
flags, with and without trailing wildcards.

**3. Prefix-wildcard coverage.** `git push --force*` covers both
`--force` and `--force-with-lease`. Without the trailing wildcard on the
flag itself, you're denying one and not the other. Same idea applies to
`mkfs.*` covering `mkfs.ext4`, `mkfs.xfs`, etc.

**4. Scope variants.** `systemctl stop *` and `systemctl --user stop *`
are different strings; both need denying. Same shape for bare `git`
versus `git -C *`. We doubled most of the `git`-based denies for the
`-C *` form.

**5. Inadvertent-mutation surfaces.** Bare `git branch <name>` and
`git tag <name>` create refs — they look read-only but aren't. Worth a
pass through the allow list specifically looking for "is this actually
read-only?"

**6. Information-disclosure surfaces.** `uname -a`, `env`, `history`,
`git log -p`, `gh run view --log`. These don't mutate but can leak.
We accepted most of them (the audit needs to ship); the point of the
class is to make the acceptance conscious.

**7. Long-flag equivalents.** `--recursive` vs `-R` vs `-r`. We denied
`chmod -R *` on round 1 and missed `chmod --recursive *` until round 4.

**8. Alternate-syntax mutations.** `git push origin :branch` deletes the
remote branch via colon syntax. Most denies for `git push` miss this
form. Our final deny list has `git -C * push * --delete *` for the
modern form; the colon syntax is in accepted gaps as archaic-low-risk.

**9. Environment-runner bypass.** The official docs explicitly call out
that `npx`, `docker exec`, `devbox run`, `direnv exec`, and `mise exec`
are **not** in the process-wrapper strip list. An allow rule for
`Bash(devbox run *)` grants whatever follows the `run` — including
denied commands. Anything that takes arbitrary arguments as a command
is a back door. The fix: write specific inner-command rules like
`Bash(devbox run npm test)`, not wildcard outer-command rules.

## Matcher limits to document, not chase

The matcher is not a security boundary. It's a heuristic. Some of its
limits you can paper over by adding more rules; others you can't.

**Pipe and compound-command handling.** The official docs state pipes
(`|`, `|&`), `&&`, `||`, `;`, `&`, and newlines are all recognized
separators, and each subcommand must match independently. In practice,
[issue #13340](https://github.com/anthropics/claude-code/issues/13340)
("global/local `settings.json` allow permissions are not respected") has
been open since 2025-12-07 with mixed reports — some users say a fix
shipped in v2.1.19; others through 2026-04 report it still misbehaves
on various pipe and prefix-rule cases. Treat the documented behavior
as the design intent and the issue thread as evidence the
implementation has rough edges. Defense-in-depth, not load-bearing.

**`~` and `$HOME` expansion in patterns.** Open question. The matcher
likely operates on the literal command string before shell expansion,
which would mean `Bash(rm -rf ~)` blocks the literal string `rm -rf ~`
but not `rm -rf /home/$USER`. We list both `~` and `$HOME` forms in the
deny list defensively. To probe in your own environment: deny
`Bash(rm -rf ~)`, then try `rm -rf /tmp/x`. If it prompts, the matcher
saw the literal `~` and `$HOME` is documentation-only.

**`.` in patterns.** Open question. Treated as a literal character or
as a regex metacharacter? Worth a contrived probe if you care; we
didn't.

**Exec wrappers that always prompt.** `watch`, `setsid`, `ionice`,
and `flock` always prompt and cannot be auto-approved by a prefix
rule like `Bash(watch *)`. Their job is to execute arbitrary inner
commands, so the prefix-rule shape doesn't fit.

**`find` with `-exec` or `-delete` (and unquoted globs on
mutate-capable commands).** Separate case from the exec wrappers,
though it lands in the same place. `find` itself is in the built-in
read-only set, but the docs carve out exceptions for `-exec` and
`-delete` (which mutate), and for unquoted globs on commands whose
flags can mutate — `find`, `sort`, `sed`, `git` — because the glob
could expand to a destructive flag. A `Bash(find *)` rule does *not*
cover `find . -delete`; write an exact-match rule for the full
command string instead.

Both cases are matcher limits in the opposite direction from gap
class 9: legitimate prefix rules *won't* auto-approve those forms.
Not something the audit can fix; just know it.

**Process wrappers that ARE stripped.** `timeout`, `time`, `nice`,
`nohup`, `stdbuf`, and bare `xargs` (with no flags) are stripped
before matching. So `Bash(npm test *)` covers `timeout 30 npm test`.
Useful to know when reasoning about whether a rule covers a wrapped
invocation. Note that `xargs -n1 grep ...` is *not* stripped — only
bare `xargs`.

**Active matcher bugs to cite honestly:**

- [#13340](https://github.com/anthropics/claude-code/issues/13340) —
  allow rules not respected for various pipe and prefix cases. Open
  since 2025-12, mixed-fix reports through 2026-04.
- [#41259](https://github.com/anthropics/claude-code/issues/41259) —
  permissions not respected after the Edit tool modifies
  `settings.local.json`. Open.

These are the reason "matcher is defense-in-depth, not primary defense"
is not a defensive disclaimer — it's the actual security model.

**Combinatorial limits.** `rm -r -f` with separated flags. `rm --recursive
--force` long-flag. `rm -Rf` capital-R. You can enumerate these and we
did some, but at some point you accept the gap. See "Documented
accepted gaps."

## A note on the built-in read-only set

The official docs name a built-in set of bash commands that run without
a prompt in every mode: `ls`, `cat`, `echo`, `pwd`, `head`, `tail`,
`grep`, `find`, `wc`, `which`, `diff`, `stat`, `du`, `cd`, and
read-only forms of `git`. The set is not configurable.

This affects allow-list reasoning in two ways:

- Entries like `Bash(pwd)` in our allow list are technically
  belt-and-suspenders — `pwd` would run without a prompt anyway. We
  keep it as documentation of intent and as protection against the
  built-in set changing in a future release.
- Entries that look like they should be built-in but aren't:
  `whoami`, `id`, `groups`, `hostname`, `date`, and version commands
  (`node --version`, `git --version`, etc.). Those carry real weight.
  If you're trimming, trim `pwd`; don't trim `whoami`.

## Worked example: a six-round audit

Round 1 produced an initial draft of roughly 68 allows and 33 denies —
the obvious destructive patterns (`rm -rf /`, `sudo *`, `dd *`,
`mkfs *`, the disk-utility family, system control, basic
`git push --force`).

Rounds 2 through 6 each surfaced a new gap class as we walked the list
against the catalog above. The deny list nearly doubled to 67; the
allow list moved less. Most of the audit's value lived in the deny
list growth.

**The drift case worth highlighting.** Our audit explicitly rejected
`Bash(gh api *)` as too broad. Reasoning: `--method POST/PUT/DELETE/PATCH`
on any endpoint enables mutation, so a single wildcard rule grants
authenticated writes to anything the token can reach. The audit's
accepted-gaps section had it as "case-by-case, do not allow with
wildcard." This aligns with the official docs' broader warning that
matcher-based argument constraints are fragile, and with the specific
recommendation to deny `curl`/`wget`-class commands.

Months after the audit, the live config had `Bash(gh api *)` back in
allows. There was no issue at the time of audit-vs-live reconciliation;
the recommendation had simply drifted. We removed it again.

This is the failure mode the iterative method exists to catch.
**The audit is a snapshot. The live config drifts.** Re-running the
audit catches drift. A one-shot audit doesn't. If we run the audit a
third time and `gh api *` is there a third time, that's a signal to
re-examine the reasoning — maybe the team needs the command and the
audit reasoning is wrong for this team. But the drift itself is the
load-bearing thing to catch, not any specific entry.

## Documented accepted gaps

We don't catch everything. Below are gaps we know about, considered,
and explicitly chose not to close.

- **Colon-syntax remote delete** (`git push origin :branch`): archaic
  form, low likelihood, accept.
- **`git stash drop/clear/pop`, `git worktree remove/prune`,
  `git checkout/restore`** discarding work: denying breaks normal
  agent flow; we trust agent judgment.
- **`rm -r -f` with separated flags, `rm --recursive --force`,
  `rm -Rf` capital-R**: combinatorial. We denied the common forms; some
  long-flag and case variants are accepted as known gaps.
- **`chmod --recursive`, `chown --recursive`, `chgrp --recursive`**
  long-flag: combinatorial, accept.
- **`git log -p`, `git show`, `gh run view --log`**: may disclose
  historical secrets. User-aware; accept.
- **`id`, `groups`, `whoami`, `hostname`**: disclose identity.
  The agent needs them; accept.
- **`init 0/6`, `telinit *`**: archaic SysV. Accept.
- **`git symbolic-ref -d`**: niche. Accept.
- **`gh api *`**: rejected as too broad (`--method` enables arbitrary
  mutation); case-by-case approval only.
- **`env`, `history`**: information disclosure; case-by-case.
- **`sed *`, `awk *`, `curl *`**: `-i` and output redirection mutate.
  Case-by-case. For `curl`/`wget` specifically, the official docs
  recommend denying outright and using `WebFetch(domain:...)`
  permissions for allowed domains. Prefer that to matcher-based URL
  constraints.
- **Pipe-to-shell denies (`curl * | sh`)**: covered by the
  per-subcommand matching rule when it works. See pipe-handling
  caveat above.
- **Fork bomb, `kill -9 1`, `killall -9 *`**: security theater;
  legitimate uses exist. Accept.

## A note on hooks

The official docs recommend a different shape of solution for the
"approve everything except specific cases" workflow: set `"Bash"` in
allows and register a PreToolUse hook that rejects the specific
commands you want blocked. Hooks see the full command string and can
parse it properly, including pipes and compound commands. They aren't
fragile in the way matchers are. Hook precedence also works in your
favor: an exit-2 hook block takes precedence over allow rules.

If you're willing to write and maintain a hook, that's strictly better
than a long deny list. This methodology is for the case where you
can't or won't write the hook — or where you want the deny list as a
second layer behind the hook.

## Appendix: example lists

The 72 allows and 67 denies below are **one team's output after six
audit rounds**, not recommended defaults. Don't copy them; audit your
own list using the method.

A few preamble notes:

- **Syntax is space-form** (`Bash(cmd *)`). Equivalent to colon-form
  (`Bash(cmd:*)`) for trailing wildcards per the official docs.
  Space-form is what the permission dialog writes when you select
  "Yes, don't ask again." The colon form is only recognized at the
  end of a pattern; mid-pattern colons are treated as literal
  characters and won't match.
- **`pwd` and read-only `git` forms are in the built-in read-only
  set** and would run without a prompt anyway. Kept for documentation
  of intent.
- **`whoami`, `id`, `groups`, `hostname`, `date`, and version commands
  are NOT in the built-in read-only set.** Those entries carry actual
  weight.
- **The live config is wider than what's published here.** The
  published lists are the audited read-only / destructive-deny core.
  The full live config also has MCP server allows, `WebFetch(domain:...)`
  rules, Skill allows, and project-specific bash mutators — those are
  out of scope for this method.
- **`$HOME` in deny rules is a placeholder for readability.** Whether
  the matcher expands `$HOME` is an open question (see "Matcher
  limits"). If it doesn't, substitute your literal home path. The `~`
  forms are listed separately and cover the tilde-form independently.

### Allows (72)

```
Bash(pwd)
Bash(whoami)
Bash(id)
Bash(groups)
Bash(hostname)
Bash(uname)
Bash(uname -s)
Bash(uname -m)
Bash(uname -r)
Bash(uname -p)
Bash(date)
Bash(node --version)
Bash(npm --version)
Bash(python --version)
Bash(python3 --version)
Bash(go version)
Bash(rustc --version)
Bash(docker --version)
Bash(git --version)
Bash(gh --version)
Bash(jq --version)
Bash(rg --version)
Bash(bash --version)
Bash(gh auth status)
Bash(gh pr view *)
Bash(gh pr list *)
Bash(gh pr diff *)
Bash(gh pr status)
Bash(gh pr checks *)
Bash(gh issue view *)
Bash(gh issue list *)
Bash(gh repo view *)
Bash(gh repo list *)
Bash(gh release view *)
Bash(gh release list *)
Bash(gh run view *)
Bash(gh run list *)
Bash(gh workflow view *)
Bash(gh workflow list *)
Bash(git -C * status)
Bash(git -C * status --short)
Bash(git -C * branch --list)
Bash(git -C * branch --list *)
Bash(git -C * branch -a)
Bash(git -C * branch -r)
Bash(git -C * branch --show-current)
Bash(git -C * tag --list)
Bash(git -C * tag --list *)
Bash(git -C * tag -l *)
Bash(git -C * worktree list)
Bash(git -C * stash list)
Bash(git -C * stash show *)
Bash(git -C * remote -v)
Bash(git -C * remote show *)
Bash(git -C * rev-parse *)
Bash(git -C * rev-list *)
Bash(git -C * ls-files)
Bash(git -C * ls-files *)
Bash(git -C * ls-tree *)
Bash(git -C * cat-file *)
Bash(git -C * shortlog)
Bash(git -C * shortlog *)
Bash(git -C * reflog)
Bash(git -C * describe)
Bash(git -C * describe *)
Bash(git -C * blame *)
Bash(git -C * grep *)
Bash(git -C * log)
Bash(git -C * log *)
Bash(git -C * show *)
Bash(git -C * diff)
Bash(git -C * diff *)
```

### Denies (67)

```
Bash(git push --force *)
Bash(git push --force)
Bash(git push -f *)
Bash(git push -f)
Bash(git push --force-with-lease *)
Bash(git push --force-with-lease)
Bash(git -C * push --force *)
Bash(git -C * push --force)
Bash(git -C * push -f *)
Bash(git -C * push -f)
Bash(git -C * push --force-with-lease *)
Bash(git -C * push --force-with-lease)
Bash(rm -rf /)
Bash(rm -rf /*)
Bash(rm -rf ~)
Bash(rm -rf ~/*)
Bash(rm -rf $HOME)
Bash(rm -rf $HOME/*)
Bash(rm -rf .)
Bash(rm -rf ..)
Bash(rm -fr /)
Bash(rm -fr /*)
Bash(rm -fr ~)
Bash(rm -fr ~/*)
Bash(rm -fr $HOME)
Bash(rm -fr $HOME/*)
Bash(rm -fr .)
Bash(rm -fr ..)
Bash(sudo *)
Bash(su)
Bash(su *)
Bash(chmod -R *)
Bash(chown -R *)
Bash(chgrp -R *)
Bash(dd *)
Bash(mkfs *)
Bash(mkfs.*)
Bash(fdisk *)
Bash(parted *)
Bash(gdisk *)
Bash(cgdisk *)
Bash(cfdisk *)
Bash(sfdisk *)
Bash(wipefs *)
Bash(shutdown *)
Bash(reboot *)
Bash(halt *)
Bash(poweroff *)
Bash(systemctl stop *)
Bash(systemctl disable *)
Bash(systemctl mask *)
Bash(systemctl kill *)
Bash(systemctl --user stop *)
Bash(systemctl --user disable *)
Bash(systemctl --user mask *)
Bash(systemctl --user kill *)
Bash(eval *)
Bash(exec *)
Bash(git -C * reset --hard *)
Bash(git -C * clean -f *)
Bash(git -C * filter-branch *)
Bash(git -C * filter-repo *)
Bash(git -C * update-ref -d *)
Bash(git -C * reflog expire *)
Bash(git -C * gc --prune*)
Bash(git -C * push --force*)
Bash(git -C * push * --delete *)
```

---

License: CC-BY 4.0. Attribution welcome; adaptation encouraged.
