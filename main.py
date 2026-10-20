
from pathlib import Path
from collections import Counter
from datetime import datetime

# Find files relative to this Python script
BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "sample.log"
REPORT_FILE = BASE_DIR / "report.txt"

FAILED_LOGIN_THRESHOLD = 3


def analyze_log_file(log_file, threshold=FAILED_LOGIN_THRESHOLD):
    """Analyze security logs and return summary data."""

    failed_logins = Counter()
    unauthorized_ips = Counter()
    total_lines = 0
    successful_logins = 0

    with Path(log_file).open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            total_lines += 1

            if "Login successful" in line:
                successful_logins += 1

            if "Failed login" in line:
                ip_address = line.rsplit(" from ", 1)[-1].strip()
                failed_logins[ip_address] += 1

            if "Unauthorized access attempt" in line:
                ip_address = line.rsplit(" from ", 1)[-1].strip()
                unauthorized_ips[ip_address] += 1

    alerts = {
        ip: count
        for ip, count in failed_logins.most_common()
        if count >= threshold
    }

    return {
        "total_lines": total_lines,
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "unauthorized_ips": unauthorized_ips,
        "alerts": alerts,
    }


def create_report(results):
    """Convert analysis results into a readable report."""

    failed = results["failed_logins"]
    unauthorized = results["unauthorized_ips"]
    alerts = results["alerts"]

    lines = [
        "CYBERSECURITY LOG ANALYSIS REPORT",
        "=" * 35,
        f"Analysis time: {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"Total log entries: {results['total_lines']}",
        f"Successful logins: {results['successful_logins']}",
        f"Failed login attempts: {sum(failed.values())}",
        f"Unauthorized access events: {sum(unauthorized.values())}",
        "",
        "REPEATED FAILED LOGIN ALERTS",
        "-" * 35,
    ]

    if alerts:
        for ip, count in alerts.items():
            lines.append(f"ALERT: {ip} had {count} failed login attempts.")
    else:
        lines.append("No repeated failed login patterns detected.")

    lines.extend(["", "UNAUTHORIZED ACCESS EVENTS", "-" * 35])

    if unauthorized:
        for ip, count in unauthorized.most_common():
            lines.append(
                f"WARNING: {ip} appeared in "
                f"{count} unauthorized access event(s)."
            )
    else:
        lines.append("No unauthorized access events found.")

    lines.extend([
        "",
        "Note: Alerts indicate suspicious patterns, not proof of an attack."
    ])

    return "\n".join(lines)


def main():
    """Run the analyzer and save its report."""

    if not LOG_FILE.is_file():
        print(f"Error: Log file not found: {LOG_FILE}")
        return

    try:
        results = analyze_log_file(LOG_FILE)
    except (OSError, UnicodeError) as error:
        print(f"Error reading log file: {error}")
        return

    report = create_report(results)
    print("\n" + report)

    try:
        REPORT_FILE.write_text(report + "\n", encoding="utf-8")
    except OSError as error:
        print(f"Could not save report: {error}")
        return

    print(f"\nReport saved to: {REPORT_FILE}")


if __name__ == "__main__":
    main()

