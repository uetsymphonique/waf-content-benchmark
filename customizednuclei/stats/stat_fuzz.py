import argparse
import csv
from pathlib import Path


def parse_int(value: str) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def parse_keys(raw: str) -> list[str]:
    return [k.strip() for k in str(raw).split(",") if k.strip()]


def match_key(template_id: str, keys: list[str], case_sensitive: bool) -> str | None:
    source = template_id if case_sensitive else template_id.lower()
    for key in keys:
        needle = key if case_sensitive else key.lower()
        if needle in source:
            return key
    return None


def aggregate(csv_path: Path, keys: list[str], case_sensitive: bool, include_unmatched: bool):
    required_columns = {
        "template_id",
        "requests_fired",
        "prevented_count",
        "bypassed_count",
        "errored_count",
    }

    use_key_filter = len(keys) > 0
    by_key = {
        key: {
            "requests_fired": 0,
            "prevented_count": 0,
            "bypassed_count": 0,
            "errored_count": 0,
        }
        for key in keys
    }
    if include_unmatched and use_key_filter:
        by_key["__unmatched__"] = {
            "requests_fired": 0,
            "prevented_count": 0,
            "bypassed_count": 0,
            "errored_count": 0,
        }

    total_rows = 0
    matched_rows = 0
    unmatched_rows = 0

    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        headers = set(reader.fieldnames or [])
        missing = required_columns - headers
        if missing:
            raise ValueError("CSV missing required columns: " + ", ".join(sorted(missing)))

        for row in reader:
            total_rows += 1
            template_id = str(row.get("template_id", "")).strip()
            requests_fired = parse_int(row.get("requests_fired"))
            prevented_count = parse_int(row.get("prevented_count"))
            bypassed_count = parse_int(row.get("bypassed_count"))
            errored_count = parse_int(row.get("errored_count"))

            key = match_key(template_id, keys, case_sensitive) if use_key_filter else template_id
            if key is None:
                unmatched_rows += 1
                if include_unmatched and use_key_filter:
                    bucket = by_key["__unmatched__"]
                    bucket["requests_fired"] += requests_fired
                    bucket["prevented_count"] += prevented_count
                    bucket["bypassed_count"] += bypassed_count
                    bucket["errored_count"] += errored_count
                continue

            matched_rows += 1
            if key not in by_key:
                by_key[key] = {
                    "requests_fired": 0,
                    "prevented_count": 0,
                    "bypassed_count": 0,
                    "errored_count": 0,
                }
            bucket = by_key[key]
            bucket["requests_fired"] += requests_fired
            bucket["prevented_count"] += prevented_count
            bucket["bypassed_count"] += bypassed_count
            bucket["errored_count"] += errored_count

    return {
        "group_mode": "key_filter" if use_key_filter else "template_id",
        "total_rows": total_rows,
        "matched_rows": matched_rows,
        "unmatched_rows": unmatched_rows,
        "by_key": by_key,
    }


def build_sorted_rows(result: dict, sort_by: str, sort_dir: str) -> list[tuple[str, dict, float]]:
    rows = []
    for key, stats in result["by_key"].items():
        requests_fired = stats["requests_fired"]
        prevented = stats["prevented_count"]
        block_rate = (prevented / requests_fired * 100.0) if requests_fired else 0.0
        rows.append((key, stats, block_rate))

    is_desc = sort_dir == "desc"

    if sort_by == "key":
        rows.sort(key=lambda item: item[0].lower(), reverse=is_desc)
    elif sort_by == "requests_fired":
        rows.sort(
            key=lambda item: (
                -item[1]["requests_fired"] if is_desc else item[1]["requests_fired"],
                item[0].lower(),
            )
        )
    elif sort_by == "prevented_count":
        rows.sort(
            key=lambda item: (
                -item[1]["prevented_count"] if is_desc else item[1]["prevented_count"],
                item[0].lower(),
            )
        )
    elif sort_by == "bypassed_count":
        rows.sort(
            key=lambda item: (
                -item[1]["bypassed_count"] if is_desc else item[1]["bypassed_count"],
                item[0].lower(),
            )
        )
    elif sort_by == "errored_count":
        rows.sort(
            key=lambda item: (
                -item[1]["errored_count"] if is_desc else item[1]["errored_count"],
                item[0].lower(),
            )
        )
    else:
        rows.sort(
            key=lambda item: (
                -item[2] if is_desc else item[2],
                item[0].lower(),
            )
        )

    return rows


def print_summary(result: dict, sort_by: str, sort_dir: str):
    print("=== Fuzz Key Stats ===")
    print(f"Group mode          : {result['group_mode']}")
    print(f"Sort by             : {sort_by}")
    print(f"Sort direction      : {sort_dir}")
    print(f"Total rows          : {result['total_rows']}")
    print(f"Rows matched keys   : {result['matched_rows']}")
    print(f"Rows unmatched      : {result['unmatched_rows']}")
    print()

    sorted_rows = build_sorted_rows(result, sort_by, sort_dir)
    key_col_width = max(24, max((len(str(k)) for k, _, _ in sorted_rows), default=0) + 4)

    print(
        f"{'key':<{key_col_width}} {'requests_fired':>14} {'prevented':>11} "
        f"{'bypassed':>10} {'errored':>9} {'block_rate':>12}"
    )
    print("-" * (key_col_width + 68))

    for key, stats, rate in sorted_rows:
        requests_fired = stats["requests_fired"]
        prevented = stats["prevented_count"]
        bypassed = stats["bypassed_count"]
        errored = stats["errored_count"]
        print(
            f"{key:<{key_col_width}} {requests_fired:>14} {prevented:>11} "
            f"{bypassed:>10} {errored:>9} {rate:>11.1f}%"
        )


def export_summary_csv(result: dict, out_path: Path, sort_by: str, sort_dir: str):
    fields = [
        "key",
        "requests_fired",
        "prevented_count",
        "bypassed_count",
        "errored_count",
        "block_rate_pct",
    ]

    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for key, stats, rate in build_sorted_rows(result, sort_by, sort_dir):
            requests_fired = stats["requests_fired"]
            prevented = stats["prevented_count"]
            bypassed = stats["bypassed_count"]
            errored = stats["errored_count"]
            writer.writerow(
                {
                    "key": key,
                    "requests_fired": requests_fired,
                    "prevented_count": prevented,
                    "bypassed_count": bypassed,
                    "errored_count": errored,
                    "block_rate_pct": f"{rate:.2f}",
                }
            )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Aggregate fuzz CSV by key strings in template_id. "
            "Each row is assigned to the first matching key in --keys order, "
            "then request metrics are summed per key. If --keys is omitted, "
            "rows are grouped by template_id."
        )
    )
    parser.add_argument("input_csv", help="Path to CSV output from fuzz mode")
    parser.add_argument(
        "--keys",
        default="",
        help="Comma-separated key list used for classification (e.g. sqli,xss,rce)",
    )
    parser.add_argument(
        "--case-sensitive",
        action="store_true",
        help="Use case-sensitive matching for key lookup",
    )
    parser.add_argument(
        "--include-unmatched",
        action="store_true",
        help="Include rows that do not match any key as __unmatched__ (only when --keys is used)",
    )
    parser.add_argument(
        "--out-csv",
        dest="out_csv",
        default="",
        help="Optional path for summary CSV output",
    )
    parser.add_argument(
        "--sort-by",
        default="block_rate",
        choices=[
            "block_rate",
            "requests_fired",
            "prevented_count",
            "bypassed_count",
            "errored_count",
            "key",
        ],
        help="Sort output rows (default: block_rate)",
    )
    parser.add_argument(
        "--sort-dir",
        default="desc",
        choices=["asc", "desc"],
        help="Sort direction (default: desc)",
    )
    args = parser.parse_args()

    input_path = Path(args.input_csv)
    if not input_path.exists():
        raise SystemExit(f"File not found: {input_path}")

    keys = parse_keys(args.keys)
    result = aggregate(
        input_path,
        keys=keys,
        case_sensitive=args.case_sensitive,
        include_unmatched=args.include_unmatched,
    )
    print_summary(result, sort_by=args.sort_by, sort_dir=args.sort_dir)

    if args.out_csv:
        out_path = Path(args.out_csv)
        export_summary_csv(result, out_path, sort_by=args.sort_by, sort_dir=args.sort_dir)
        print(f"\nSummary CSV written: {out_path}")


if __name__ == "__main__":
    main()
