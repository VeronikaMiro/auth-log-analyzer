
---

## 2) analyzer.py
Vlož do `analyzer.py`:

```python
import re
from collections import Counter
from pathlib import Path

LOG_FILE = "sample_auth.log"
REPORT_FILE = "output_report.txt"
SUSPICIOUS_THRESHOLD = 3

FAILED_PATTERNS = [
    r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)",
    r"authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)",
]

SUCCESS_PATTERNS = [
    r"Accepted password for .* from (\d+\.\d+\.\d+\.\d+)",
]


def extract_ip(line: str, patterns: list[str]) -> str | None:
    """Try to extract an IP address from a log line using known patterns."""
    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            return match.group(1)
    return None


def analyze_log(file_path: str) -> tuple[Counter, Counter]:
    """Analyze log file and return failed and successful login counts by IP."""
    failed_counts = Counter()
    success_counts = Counter()

    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            failed_ip = extract_ip(line, FAILED_PATTERNS)
            if failed_ip:
                failed_counts[failed_ip] += 1
                continue

            success_ip = extract_ip(line, SUCCESS_PATTERNS)
            if success_ip:
                success_counts[success_ip] += 1

    return failed_counts, success_counts


def generate_report(failed_counts: Counter, success_counts: Counter, threshold: int) -> str:
    """Generate a human-readable report."""
    suspicious_ips = {ip: count for ip, count in failed_counts.items() if count >= threshold}

    lines = []
    lines.append("AUTH LOG ANALYSIS REPORT")
    lines.append("=" * 30)
    lines.append("")

    lines.append("Failed login attempts by IP:")
    if failed_counts:
        for ip, count in failed_counts.most_common():
            lines.append(f"- {ip}: {count}")
    else:
        lines.append("- None found")

    lines.append("")
    lines.append("Successful login attempts by IP:")
    if success_counts:
        for ip, count in success_counts.most_common():
            lines.append(f"- {ip}: {count}")
    else:
        lines.append("- None found")

    lines.append("")
    lines.append(f"Suspicious IPs (threshold: {threshold}+ failed attempts):")
    if suspicious_ips:
        for ip, count in sorted(suspicious_ips.items(), key=lambda item: item[1], reverse=True):
            lines.append(f"- {ip}: {count} failed attempts")
    else:
        lines.append("- None found")

    return "\n".join(lines)


def save_report(report: str, file_path: str) -> None:
    """Save the report to a file."""
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(report)


def main() -> None:
    try:
        failed_counts, success_counts = analyze_log(LOG_FILE)
        report = generate_report(failed_counts, success_counts, SUSPICIOUS_THRESHOLD)
        save_report(report, REPORT_FILE)

        print(report)
        print(f"\nReport saved to: {REPORT_FILE}")

    except FileNotFoundError as error:
        print(f"Error: {error}")
    except Exception as error:
        print(f"Unexpected error: {error}")


if __name__ == "__main__":
    main()
