#!/usr/bin/env bash
set -euo pipefail

mode="${1:---full}"
case "$mode" in
  --staged|--full|--ci) ;;
  *)
    echo "usage: scripts/audit.sh [--staged|--full|--ci]" >&2
    exit 2
    ;;
esac

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

if [[ "$mode" == "--staged" ]] && git diff --cached --quiet; then
  echo "audit: no staged changes"
  exit 0
fi

failures=0

fail() {
  echo "audit: FAIL: $*" >&2
  failures=1
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "missing required tool: $1"
  fi
}

for tool in git grep find python3 gitleaks trufflehog git-secrets detect-secrets; do
  require_tool "$tool"
done

if [[ "$failures" -ne 0 ]]; then
  echo "audit: install the missing tools, then retry" >&2
  exit 1
fi

check_empty() {
  local label="$1"
  local output="$2"
  if [[ -n "$output" ]]; then
    fail "$label"
    echo "$output" >&2
  fi
}

scan_pattern() {
  local label="$1"
  local pattern="$2"
  local matches
  matches="$(grep -R -I -n -E \
    --exclude-dir=.git \
    --exclude='audit.sh' \
    "$pattern" . || true)"
  check_empty "$label" "$matches"
}

echo "audit: checking repository hygiene"

tracked_env_files="$(git ls-files | grep -E '(^|/)\.env($|\.)' | grep -v -E '(^|/)\.env\.example$' || true)"
check_empty "tracked private environment file" "$tracked_env_files"

sensitive_filenames="$(git ls-files | grep -E '(^|/)(id_rsa|id_ed25519|GoogleService-Info\.plist|Secrets\.plist|.*\.(mobileprovision|provisionprofile|p12|pfx|pem|key|cer|crt))$' || true)"
check_empty "tracked credential-like filename" "$sensitive_filenames"

local_xcode_config="$(git ls-files | grep -E '(^|/)(ExportOptions\.plist|.*\.xcconfig|.*\.xcarchive(/|$))' | grep -v -E '\.xcconfig\.example$' || true)"
check_empty "tracked local Xcode signing/config file" "$local_xcode_config"

for path in Pods Carthage LocalPackages vendor node_modules; do
  if [[ -e "$path" ]]; then
    fail "unexpected vendored dependency path: $path"
  fi
done

vendored_binaries="$(find . -path ./.git -prune -o -type f \( -name '*.framework' -o -name '*.xcframework' -o -name '*.a' -o -name '*.dylib' -o -name '*.so' \) -print)"
check_empty "unexpected vendored binary artifact" "$vendored_binaries"

large_files="$(find . -path ./.git -prune -o -type f -size +5M -print)"
check_empty "file larger than 5 MB" "$large_files"

if [[ ! -f LICENSE ]] || ! grep -q '^MIT License$' LICENSE; then
  fail "LICENSE must be present and MIT"
fi

scan_pattern "credentialed URL" '[A-Za-z][A-Za-z0-9+.-]*://[^[:space:]@/]+:[^[:space:]@/]+@'
scan_pattern "default MinIO credential" 'mini[[:alpha:]]admin'
scan_pattern "dev-only token pepper" 'dev[-]only[-]pepper'
scan_pattern "forbidden LibSignal or AGPL reference" 'A[G]PL|A[f]fero|GNU A[f]fero|Lib[S]ignal|lib[s]ignal|signalapp'
scan_pattern "Apple development team id" 'DEVELOPMENT[_]TEAM[[:space:]]*=[[:space:]]*"?[A-Z0-9]{10}"?[[:space:]]*;'
scan_pattern "Apple provisioning profile setting" 'PROVISIONING[_]PROFILE(_SPECIFIER)?[[:space:]]*='
scan_pattern "Apple signing certificate identity" 'CODE[_]SIGN[_]IDENTITY[[:space:]]*=[[:space:]]*"?(Apple Development|iPhone Developer|Developer ID|[^";]*\([A-Z0-9]{10}\))'
scan_pattern "Apple export signing metadata" '<key>(teamID|teamIdentifier|signingCertificate|provisioningProfiles)</key>'
scan_pattern "Apple team-scoped entitlement" 'com\.apple\.developer\.team-identifier|application-identifier|keychain-access-groups|com\.apple\.security\.application-groups|com\.apple\.developer\.icloud-container-identifiers|merchant\.[A-Za-z0-9.-]+'
scan_pattern "private IPv4 address" '(^|[^0-9])(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})([^0-9]|$)'
scan_pattern "absolute personal home path" '/(Users|home)/[[:alnum:]_.-]+'
scan_pattern "private key block" 'BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY'
scan_pattern "GitHub token" 'ghp_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+'
scan_pattern "AWS access key" 'AKIA[0-9A-Z]{16}'
scan_pattern "Google API key" 'AIza[0-9A-Za-z_-]{35}'
scan_pattern "OpenAI-style API key" 'sk-[A-Za-z0-9]{20,}'

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi

echo "audit: running gitleaks history scan"
gitleaks detect --source . --redact --verbose

echo "audit: running gitleaks worktree scan"
gitleaks dir . --redact --no-banner --verbose

echo "audit: running TruffleHog filesystem scan"
trufflehog filesystem --no-update --fail --no-verification .

echo "audit: running git-secrets scan"
git-secrets --scan -r .

echo "audit: running detect-secrets scan"
detect_json="$(mktemp)"
trap 'rm -f "$detect_json"' EXIT
detect-secrets scan --all-files --exclude-files '^\.git/' > "$detect_json"
python3 - "$detect_json" <<'PY'
import json
import pathlib
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)

findings = []
for filename, items in data.get("results", {}).items():
    path = pathlib.Path(filename)
    lines = []
    if path.exists():
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for item in items:
        line_number = int(item.get("line_number") or 0)
        line = lines[line_number - 1] if 0 < line_number <= len(lines) else ""
        allowed_xcode_id = (
            filename == "Gotogo.xcodeproj/xcshareddata/xcschemes/Gotogo.xcscheme"
            and "BlueprintIdentifier" in line
        )
        if not allowed_xcode_id:
            findings.append((filename, line_number, item.get("type", "unknown")))

if findings:
    for filename, line_number, kind in findings:
        print(f"detect-secrets finding: {filename}:{line_number}: {kind}", file=sys.stderr)
    sys.exit(1)

print("detect-secrets: no actionable findings")
PY

if [[ "$mode" == "--full" ]] && command -v xcodebuild >/dev/null 2>&1; then
  echo "audit: running iOS simulator build"
  xcodebuild \
    -project Gotogo.xcodeproj \
    -scheme Gotogo \
    -destination 'generic/platform=iOS Simulator' \
    CODE_SIGNING_ALLOWED=NO \
    build
fi

echo "audit: passed"
