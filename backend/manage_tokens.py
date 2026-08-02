#!/usr/bin/env python3

import argparse
import sys

import token_store


def cmd_create(args):
    quota_bytes = int(args.quota_gb * 1024**3) if args.quota_gb is not None else None
    token = token_store.create_token(label=args.label, quota_bytes=quota_bytes)
    quota_display = f"{args.quota_gb} GB" if args.quota_gb is not None else f"{token_store.DEFAULT_QUOTA_BYTES / 1024**3:g} GB (default)"
    print(f"Token created for {args.label or '(unlabeled)'}:")
    print(f"  {token}")
    print(f"Quota: {quota_display}")
    print("Not yet bound to a vault — it will bind automatically to whichever")
    print("vault first uploads with it. Give this token to the person who")
    print("should use it; they enter it in the app alongside their passphrase.")


def cmd_list(args):
    tokens = token_store.list_tokens()
    if not tokens:
        print("No tokens configured yet. Create one with: python manage_tokens.py create")
        return
    for token, record in tokens.items():
        label = record.get("label") or "(unlabeled)"
        vault_id = record.get("vault_id")
        quota = record.get("quota_bytes")
        quota_display = f"{quota / 1024**3:g} GB" if quota is not None else f"{token_store.DEFAULT_QUOTA_BYTES / 1024**3:g} GB (default)"
        status = f"bound to vault {vault_id[:12]}..." if vault_id else "unbound (not yet used)"
        print(f"{token}")
        print(f"  label: {label}")
        print(f"  quota: {quota_display}")
        print(f"  status: {status}")


def cmd_revoke(args):
    if token_store.revoke_token(args.token):
        print("Revoked.")
    else:
        print("No such token.", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create", help="Create a new, unbound access token")
    p_create.add_argument("--label", help="A human-readable note (e.g. a name) — never sent to clients")
    p_create.add_argument("--quota-gb", type=float, help=f"Storage quota in GB (default: {token_store.DEFAULT_QUOTA_BYTES / 1024**3:g})")
    p_create.set_defaults(func=cmd_create)

    p_list = sub.add_parser("list", help="List all tokens and their status")
    p_list.set_defaults(func=cmd_list)

    p_revoke = sub.add_parser("revoke", help="Delete a token, blocking further uploads with it")
    p_revoke.add_argument("token")
    p_revoke.set_defaults(func=cmd_revoke)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
