#!/usr/bin/env python3

import argparse
import csv
import io
import json
import os
import sys
import urllib.request
import urllib.error

from nids_capture import create_streamer, flow_to_row, OUTPUT_COLUMNS


## Flow extraction

def capture_flows(source, bpf_filter=None):
    streamer = create_streamer(source, bpf_filter)
    rows = []
    try:
        for flow in streamer:
            rows.append(flow_to_row(flow))
            if len(rows) % 1000 == 0:
                print(f"[ai_nids_cli] {len(rows)} flows extracted...", file=sys.stderr)
    except KeyboardInterrupt:
        print(f"\n[ai_nids_cli] Stopped. {len(rows)} flows extracted.", file=sys.stderr)
    return rows


def rows_to_csv(rows):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=OUTPUT_COLUMNS)
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()

## Lambda classification

def classify(csv_data, api_url, api_key):
    req = urllib.request.Request(
        api_url,
        data=csv_data.encode("utf-8"),
        headers={"x-api-key": api_key, "Content-Type": "text/plain"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            body = json.loads(resp.read())
            # Unwrap API Gateway envelope if present
            if isinstance(body, dict) and "body" in body:
                body = json.loads(body["body"])
            return body
    except urllib.error.HTTPError as e:
        print(f"[ai_nids_cli] HTTP {e.code}: {e.read().decode()}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"[ai_nids_cli] Could not reach API: {e.reason}", file=sys.stderr)
        print(f"[ai_nids_cli] Check that --api-url is correct: {api_url}", file=sys.stderr)
        sys.exit(1)

## Results display

def print_results(results):
    print("\n" + "=" * 52)
    print("  CLASSIFICATION RESULTS")
    print("=" * 52)
    for model_name, metrics in results.items():
        print(f"\n  Model: {model_name.upper()}")
        if "predictions" in metrics:
            preds  = metrics["predictions"]
            total      = len(preds)
            malicious  = sum(1 for p in preds if p == 1)
            benign     = total - malicious
            print(f"  {'Total flows':<14} {total}")
            print(f"  {'Benign':<14} {benign}  ({benign / total * 100:.1f}%)")
            print(f"  {'Malicious':<14} {malicious}  ({malicious / total * 100:.1f}%)")
        elif "confusion_matrix" in metrics:
            [[tn, fp], [fn, tp]] = metrics["confusion_matrix"]
            print(f"  TP: {tp:<6} FP: {fp:<6} TN: {tn:<6} FN: {fn}")
            if "classification_report" in metrics:
                r = metrics["classification_report"]
                print(f"\n  {'Class':<16} {'Precision':>10} {'Recall':>10} {'F1-Score':>10} {'Support':>10}")
                print(f"  {'-'*56}")
                for cls in ["0", "1", "macro avg", "weighted avg"]:
                    if cls in r:
                        cr = r[cls]
                        print(
                            f"  {cls:<16}"
                            f" {cr.get('precision', 0):>10.3f}"
                            f" {cr.get('recall', 0):>10.3f}"
                            f" {cr.get('f1-score', 0):>10.3f}"
                            f" {str(cr.get('support', '-')):>10}"
                        )
    print()



## Entry point

def main():
    parser = argparse.ArgumentParser(
        description="Extract NetFlow v3 features and classify via AI-NIDS Lambda.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python ai_nids_cli.py -i capture.pcap\n"
            "  python ai_nids_cli.py -i capture.pcap -o flows.csv\n"
            "  python ai_nids_cli.py -i capture.pcap --no-classify\n"
            "  sudo python ai_nids_cli.py -i eth0 --api-url https://....amazonaws.com/prod/predict --api-key KEY\n"
            "\n"
            "Environment variables:\n"
            "  NIDS_API_URL   API Gateway /predict endpoint\n"
            "  NIDS_API_KEY   API key\n"
        ),
    )
    parser.add_argument("-i", "--interface", required=True,
                        help="pcap file path or live interface (e.g. eth0).")
    parser.add_argument("-o", "--output", default=None,
                        help="Save extracted flows to this CSV file.")
    parser.add_argument("-f", "--filter", default=None,
                        help="BPF packet filter (e.g. 'tcp port 80').")
    parser.add_argument("--api-url", default=os.environ.get("NIDS_API_URL"),
                        help="Lambda /predict endpoint. Falls back to NIDS_API_URL env var.")
    parser.add_argument("--api-key", default=os.environ.get("NIDS_API_KEY"),
                        help="API key. Falls back to NIDS_API_KEY env var.")
    parser.add_argument("--no-classify", action="store_true",
                        help="Skip classification — only extract and optionally save flows.")
    args = parser.parse_args()

    ## Step 1: Flow Extraction
    rows = capture_flows(args.interface, args.filter)
    if not rows:
        print("[ai_nids_cli] No flows captured. Check file path and permissions.", file=sys.stderr)
        sys.exit(1)
    print(f"[ai_nids_cli] {len(rows)} flows extracted.", file=sys.stderr)

    csv_data = rows_to_csv(rows)

    ## Step 2: save CSV if requested
    if args.output:
        with open(args.output, "w", newline="") as f:
            f.write(csv_data)
        print(f"[ai_nids_cli] Flows saved to {args.output}", file=sys.stderr)

    # Step 3: Classification
    if args.no_classify:
        return

    if not args.api_url:
        print("[ai_nids_cli] --api-url is required (or set NIDS_API_URL). "
              "Use --no-classify to skip.", file=sys.stderr)
        sys.exit(1)
    if not args.api_key:
        print("[ai_nids_cli] --api-key is required (or set NIDS_API_KEY).", file=sys.stderr)
        sys.exit(1)

    print("[ai_nids_cli] Sending to Lambda classifier...", file=sys.stderr)
    results = classify(csv_data, args.api_url, args.api_key)
    print_results(results)


if __name__ == "__main__":
    main()
