"""
SentraGuard Lite CLI
---------------------
Single command as per spec:
  python cli.py analyze --input sample_request.json --output out.json

Reads input JSON -> calls POST /analyze on the running API -> writes output JSON.
"""
import argparse
import json
import os
import sys

import requests

API_BASE_URL = os.environ.get("API_BASE_URL", "http://localhost:8000")


def cmd_analyze(args):
    if not os.path.exists(args.input):
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(args.input, "r") as f:
        try:
            payload = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error: invalid JSON in input file: {e}", file=sys.stderr)
            sys.exit(1)

    url = f"{API_BASE_URL}/analyze"
    try:
        response = requests.post(url, json=payload, timeout=10)
    except requests.exceptions.ConnectionError:
        print(f"Error: could not connect to API at {url}. Is the server running?", file=sys.stderr)
        sys.exit(1)

    if response.status_code != 200:
        print(f"Error: API returned status {response.status_code}: {response.text}", file=sys.stderr)
        sys.exit(1)

    result = response.json()

    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Analysis complete. decision={result.get('decision')} risk_score={result.get('risk_score')}")
    print(f"Output written to: {args.output}")


def main():
    parser = argparse.ArgumentParser(prog="cli.py", description="SentraGuard Lite CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a request via the API")
    analyze_parser.add_argument("--input", required=True, help="Path to input JSON file")
    analyze_parser.add_argument("--output", required=True, help="Path to write output JSON file")
    analyze_parser.set_defaults(func=cmd_analyze)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
