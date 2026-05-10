"""CLI tool to encrypt exchange secrets for upload to the signer.

Usage:
    # Single-file output
    usenami-encrypt --exchange kucoin --kms-key ARN \\
        --input kucoin.json --output kucoin.enc

    # Directory output (uses {exchange}.enc filename)
    usenami-encrypt --exchange binance --kms-key ARN \\
        --input binance.json --output-dir /etc/signer/blobs/

    # Encrypt + upload to gateway
    usenami-encrypt --exchange bybit --kms-key ARN \\
        --input bybit.json --gateway URL --api-key KEY

Required JSON shape per exchange:
    kucoin:           {"key", "secret", "passphrase"}
    binance:          {"key", "secret"}
    binance_futures:  {"key", "secret"}
    bybit:            {"key", "secret"}
    okx:              {"key", "secret", "passphrase"}
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

try:
    import boto3
except ImportError:
    boto3 = None  # type: ignore[assignment]

import httpx


def encrypt_secrets(kms_key_arn: str, plaintext: bytes, region: str = "us-east-1") -> bytes:
    """Encrypt plaintext using KMS. Returns ciphertext bytes."""
    if boto3 is None:
        print("ERROR: boto3 is required for encryption. Install with: pip install boto3", file=sys.stderr)
        sys.exit(1)

    client = boto3.client("kms", region_name=region)
    response = client.encrypt(
        KeyId=kms_key_arn,
        Plaintext=plaintext,
    )
    return response["CiphertextBlob"]


def upload_to_gateway(gateway_url: str, api_key: str, ciphertext: bytes) -> None:
    """Upload encrypted blob to the signer gateway."""
    resp = httpx.post(
        f"{gateway_url.rstrip('/')}/upload",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/octet-stream",
        },
        content=base64.b64encode(ciphertext),
    )
    if resp.status_code == 200:
        print("Upload successful.")
    else:
        print(f"Upload failed: {resp.status_code} {resp.text}", file=sys.stderr)
        sys.exit(1)


_REQUIRED_FIELDS: dict[str, set[str]] = {
    "kucoin": {"key", "secret", "passphrase"},
    "binance": {"key", "secret"},
    "binance_futures": {"key", "secret"},
    "bybit": {"key", "secret"},
    "okx": {"key", "secret", "passphrase"},
}

_SUPPORTED_EXCHANGES = sorted(_REQUIRED_FIELDS.keys())


def validate_secrets_json(data: dict, exchange: str) -> None:
    """Validate the secrets JSON has the right fields for the given exchange."""
    if exchange not in _REQUIRED_FIELDS:
        print(
            f"ERROR: unsupported exchange '{exchange}'. Choose one of: "
            f"{', '.join(_SUPPORTED_EXCHANGES)}",
            file=sys.stderr,
        )
        sys.exit(1)
    required = _REQUIRED_FIELDS[exchange]
    missing = required - set(data.keys())
    if missing:
        print(
            f"ERROR: secrets JSON for '{exchange}' missing field(s): "
            f"{', '.join(sorted(missing))}",
            file=sys.stderr,
        )
        sys.exit(1)
    extra = set(data.keys()) - required
    if extra:
        print(
            f"WARNING: secrets JSON for '{exchange}' has extra field(s): "
            f"{', '.join(sorted(extra))} (will be encrypted as-is)",
            file=sys.stderr,
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="usenami-encrypt",
        description="Encrypt exchange API secrets for the Usenami Signer enclave.",
    )
    parser.add_argument(
        "--exchange",
        required=True,
        choices=_SUPPORTED_EXCHANGES,
        help="Exchange the secrets are for (kucoin/binance/binance_futures/bybit/okx)",
    )
    parser.add_argument(
        "--kms-key",
        required=True,
        help="ARN of the KMS key used by the signer enclave",
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to secrets JSON file (kucoin/okx: 3-field, binance/bybit: 2-field)",
    )
    parser.add_argument(
        "--output",
        help="Path to write encrypted blob (mutually exclusive with --gateway, --output-dir)",
    )
    parser.add_argument(
        "--output-dir",
        help="Directory to write the blob as {exchange}.enc (matches gateway --blobs-dir)",
    )
    parser.add_argument(
        "--gateway",
        help="Gateway URL to upload encrypted blob directly",
    )
    parser.add_argument(
        "--api-key",
        help="API key for gateway authentication (required with --gateway)",
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region for KMS (default: us-east-1)",
    )

    args = parser.parse_args()

    output_modes = sum(bool(x) for x in (args.output, args.output_dir, args.gateway))
    if output_modes == 0:
        parser.error("One of --output, --output-dir, --gateway is required")
    if output_modes > 1:
        parser.error("--output, --output-dir, and --gateway are mutually exclusive")
    if args.gateway and not args.api_key:
        parser.error("--api-key is required when using --gateway")

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    secrets_raw = input_path.read_bytes()
    try:
        secrets_data = json.loads(secrets_raw)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in {args.input}: {e}", file=sys.stderr)
        sys.exit(1)

    validate_secrets_json(secrets_data, args.exchange)

    print(f"Encrypting {args.exchange} secrets with KMS key: {args.kms_key}")
    ciphertext = encrypt_secrets(args.kms_key, secrets_raw, region=args.region)
    print(f"Encrypted: {len(ciphertext)} bytes ciphertext")

    if args.output:
        output_path = Path(args.output)
        output_path.write_bytes(ciphertext)
        print(f"Written to: {args.output}")
    elif args.output_dir:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"{args.exchange}.enc"
        output_path.write_bytes(ciphertext)
        print(f"Written to: {output_path}")
    elif args.gateway:
        upload_to_gateway(args.gateway, args.api_key, ciphertext)

    print(f"\nIMPORTANT: Delete {args.input} now — you won't need it again.")


if __name__ == "__main__":
    main()
