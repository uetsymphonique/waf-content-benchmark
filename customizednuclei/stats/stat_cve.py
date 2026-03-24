import argparse
import csv
from collections import defaultdict
from pathlib import Path


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}


def parse_int(value: str) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def normalize_severity(value: str) -> str:
    v = str(value or "").strip().lower()
    return v if v else "unknown"


def severity_sort_key(value: str) -> tuple[int, str]:
    v = normalize_severity(value)
    return (SEVERITY_ORDER.get(v, 999), v)


def aggregate(csv_path: Path):
    required_columns = {
        "template_id",
        "severity",
        "requests_defined",
        "requests_fired",
        "prevented_count",
    }

    by_severity = defaultdict(
        lambda: {
            "eligible_templates": 0,
            "blocked_templates": 0,
            "complete_templates": 0,
            "complete_blocked_templates": 0,
            "incomplete_blocked_templates": 0,
        }
    )

    total_rows = 0
    complete_rows = 0
    incomplete_blocked_rows = 0
    ignored_rows = 0

    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        headers = set(reader.fieldnames or [])
        missing = required_columns - headers
        if missing:
            raise ValueError(
                "CSV missing required columns: " + ", ".join(sorted(missing))
            )

        for row in reader:
            total_rows += 1

            severity = normalize_severity(row.get("severity", ""))
            requests_defined = parse_int(row.get("requests_defined"))
            requests_fired = parse_int(row.get("requests_fired"))
            prevented_count = parse_int(row.get("prevented_count"))

            is_complete = requests_fired == requests_defined
            is_blocked = prevented_count > 0
            is_incomplete_blocked = (requests_fired < requests_defined) and is_blocked
            is_eligible = is_complete or is_incomplete_blocked

            if not is_eligible:
                ignored_rows += 1
                continue

            bucket = by_severity[severity]
            bucket["eligible_templates"] += 1

            if is_blocked:
                bucket["blocked_templates"] += 1

            if is_complete:
                complete_rows += 1
                bucket["complete_templates"] += 1
                if is_blocked:
                    bucket["complete_blocked_templates"] += 1
            else:
                incomplete_blocked_rows += 1
                bucket["incomplete_blocked_templates"] += 1

    return {
        "total_rows": total_rows,
        "complete_rows": complete_rows,
        "incomplete_blocked_rows": incomplete_blocked_rows,
        "ignored_rows": ignored_rows,
        "by_severity": by_severity,
    }


def print_summary(result: dict):
    print("=== CVE Severity Stats ===")
    print(f"Total rows               : {result['total_rows']}")
    print(f"Rows included (complete) : {result['complete_rows']}")
    print(
        "Rows included (incomplete+blocked)"
        f": {result['incomplete_blocked_rows']}"
    )
    print(f"Rows ignored             : {result['ignored_rows']}")
    print()

    header = (
        "severity",
        "eligible_templates",
        "blocked_templates",
        "blocked_rate",
    )
    print(
        f"{header[0]:<10} {header[1]:>18} {header[2]:>17} {header[3]:>12}"
    )
    print("-" * 64)

    by_severity = result["by_severity"]
    for sev in sorted(by_severity.keys(), key=severity_sort_key):
        b = by_severity[sev]
        eligible = b["eligible_templates"]
        blocked = b["blocked_templates"]
        blocked_rate = (blocked / eligible * 100.0) if eligible else 0.0

        print(
            f"{sev:<10}"
            f" {eligible:>18}"
            f" {blocked:>17}"
            f" {blocked_rate:>11.1f}%"
        )


def export_summary_csv(result: dict, out_path: Path):
    fields = [
        "severity",
        "eligible_templates",
        "blocked_templates",
        "blocked_rate_pct",
    ]

    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        by_severity = result["by_severity"]
        for sev in sorted(by_severity.keys(), key=severity_sort_key):
            b = by_severity[sev]
            eligible = b["eligible_templates"]
            blocked = b["blocked_templates"]
            blocked_rate = (blocked / eligible * 100.0) if eligible else 0.0

            writer.writerow(
                {
                    "severity": sev,
                    "eligible_templates": eligible,
                    "blocked_templates": blocked,
                    "blocked_rate_pct": f"{blocked_rate:.2f}",
                }
            )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Aggregate CVE severity stats from customizednuclei CSV output. "
            "Only include complete templates or incomplete but blocked templates."
        )
    )
    parser.add_argument("input_csv", help="Path to CSV output from cve mode")
    parser.add_argument(
        "--out-csv",
        dest="out_csv",
        default="",
        help="Optional path for summary CSV output",
    )
    args = parser.parse_args()

    input_path = Path(args.input_csv)
    if not input_path.exists():
        raise SystemExit(f"File not found: {input_path}")

    result = aggregate(input_path)
    print_summary(result)

    if args.out_csv:
        out_path = Path(args.out_csv)
        export_summary_csv(result, out_path)
        print(f"\nSummary CSV written: {out_path}")


if __name__ == "__main__":
    main()
