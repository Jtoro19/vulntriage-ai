#!/usr/bin/env bash
# Fails if any tracked file contains an API key pattern or a value from .env.
# Run before every push (also installed as .git/hooks/pre-push).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
patterns='AIza[0-9A-Za-z_-]{30,}|gsk_[0-9A-Za-z]{20,}|[0-9]{8,10}:AA[0-9A-Za-z_-]{30,}|sk-[A-Za-z0-9]{20,}'
status=0
if git ls-files -z | xargs -0 rg -l -I -e "$patterns" 2>/dev/null; then
  echo "Secret pattern found in tracked files" >&2; status=1
fi
if [[ -f .env ]]; then
  while IFS='=' read -r name value; do
    [[ -z "${name}" || "${name}" == \#* || ${#value} -lt 6 ]] && continue
    if git ls-files -z | xargs -0 rg -l -I -F -e "$value" 2>/dev/null; then
      echo "Value of ${name} found in tracked files" >&2; status=1
    fi
  done < .env
fi
for f in .env _private _checklists BRIEF.md AGENTS.md CLAUDE.md GEMINI.md .envrc .mcp.json .claude; do
  if git ls-files --error-unmatch "$f" >/dev/null 2>&1 || [[ -n "$(git ls-files "$f")" ]]; then
    echo "Forbidden path tracked: $f" >&2; status=1
  fi
done
[[ $status -eq 0 ]] && echo "Secret check passed"
exit $status
