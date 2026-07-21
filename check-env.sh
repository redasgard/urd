#!/usr/bin/env bash
# Pre-flight environment check for the Urd lab — no Python required to run this.
#
# Tells you which of the three lab paths (Docker / local Python / static
# traces) you're actually on, before you spend your 3 minutes finding out the
# hard way. See TACTIC_GUIDE.md for what each path means.

echo "Urd lab -- environment check"
echo

docker_ok=0
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  docker_ok=1
  echo "  [x] Docker found and daemon is running"
elif command -v docker >/dev/null 2>&1; then
  echo "  [ ] Docker found but daemon is not running (start Docker Desktop / dockerd)"
else
  echo "  [ ] Docker not found"
fi

python_ok=0
python_cmd=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then
    ver="$("$candidate" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")' 2>/dev/null)"
    if [ -n "$ver" ]; then
      major="${ver%%.*}"
      minor="${ver##*.}"
      if [ "$major" -eq 3 ] && [ "$minor" -ge 11 ] 2>/dev/null; then
        python_ok=1
        python_cmd="$candidate"
        echo "  [x] $candidate $ver found (>= 3.11)"
        break
      elif [ "$major" -gt 3 ] 2>/dev/null; then
        python_ok=1
        python_cmd="$candidate"
        echo "  [x] $candidate $ver found (>= 3.11)"
        break
      else
        echo "  [ ] $candidate $ver found, but too old (need 3.11+)"
      fi
    fi
  fi
done
if [ "$python_ok" -eq 0 ]; then
  echo "  [ ] No Python 3.11+ found"
fi

echo
if [ "$docker_ok" -eq 1 ]; then
  echo "-> Use Docker:"
  echo "     docker compose build"
  echo "     docker compose run --rm urd-lab ./lab.sh run"
elif [ "$python_ok" -eq 1 ]; then
  echo "-> Use local Python ($python_cmd):"
  echo "     ./lab.sh run"
else
  echo "-> Neither found. That's fine -- read the attack instead:"
  echo "     see 'No laptop? Read the attack instead' in TACTIC_GUIDE.md"
fi
