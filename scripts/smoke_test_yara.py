"""Small dependency smoke test for the YARA runtime used by Volatility."""

import yara


rules = yara.compile(
    source='rule smoke { strings: $needle = "memforensics-yara-smoke" condition: $needle }'
)
matches = rules.match(data=b"prefix memforensics-yara-smoke suffix")
if not matches or matches[0].rule != "smoke":
    raise SystemExit("YARA compiled but did not match the test payload")

print(f"YARA compile and match OK (libyara {yara.__version__})")
