"""Replace lab IP addresses in a scan report with stable placeholders.

172.30.0.12 becomes lab-host-12; any other private IPv4 becomes lab-host-x.
Usage: python scripts/anonymize_scan.py <in> <out>
"""

from __future__ import annotations

import re
import sys

LAB = re.compile(r"\b172\.30\.0\.(\d{1,3})\b")
PRIVATE = re.compile(
    r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3})\.\d{1,3}(?:\.\d{1,3})?\b"
)


def anonymize(text: str) -> str:
    text = LAB.sub(lambda m: f"lab-host-{m.group(1)}", text)
    return PRIVATE.sub("lab-host-x", text)


if __name__ == "__main__":
    src, dst = sys.argv[1], sys.argv[2]
    with open(src, encoding="utf-8") as f:
        data = anonymize(f.read())
    with open(dst, "w", encoding="utf-8") as f:
        f.write(data)
