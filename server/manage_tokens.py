#!/usr/bin/env python3

import argparse
import json
import os
import sys

import token_store


def cmd_create(args):
    quota_bytes = int(args.quota_gb * 1024**3) if args.quota_gb is not None else None
    quota_display = f"{args.quota_gb} GB" if args.quota_gb is not None else f"{token_store.DEFAULT_QUOTA_BYTES / 1024**3:g} GB (default)"

    first, second = token_store.create_token_pair(label=args.label, quota_bytes=quota_bytes)

    print(f"Access tokens created for {args.label or '(unlabeled)'}:")
    print(f"  {first}")
    print(f"  {second}")
    print()
    print(f"Quota: {quota_display} each")
    print("Give both to the person. They pick one as their main token (entered in the app")
    print("alongside their password) and keep the other for the decoy vault (Duress Code")
    print("panel, under 'Decoy files'). The two are identical, so nobody, including this")
    print("server, can tell which one they chose. Each binds to whichever vault first uses it.")


def cmd_strip_decoy_labels(args):
    changed = token_store.strip_decoy_labels()
    print(f"Removed the '(decoy)' marker from {changed} token label(s)." if changed else "No '(decoy)' labels found.")


def cmd_list(args):
    tokens = token_store.list_tokens()
    if not tokens:
        print("No tokens configured yet. Create one with: python manage_tokens.py create")
        return
    print("Tokens are hashed at rest, this means the full value is only ever shown once, at creation.")
    print("Use the id below (or the raw token, if you kept it) to revoke.\n")
    for token_hash, record in tokens.items():
        label = record.get("label") or "(unlabeled)"
        vault_id = record.get("vault_id")
        quota = record.get("quota_bytes")
        quota_display = f"{quota / 1024**3:g} GB" if quota is not None else f"{token_store.DEFAULT_QUOTA_BYTES / 1024**3:g} GB (default)"
        status = f"bound to vault {vault_id[:12]}..." if vault_id else "unbound (not yet used)"
        print(f"id: {token_hash[:12]}")
        print(f"  label: {label}")
        print(f"  quota: {quota_display}")
        print(f"  status: {status}")


def cmd_revoke(args):
    if token_store.revoke_token(args.token) or token_store.revoke_by_id(args.token):
        print("Revoked.")
    else:
        print("No such token — checked both as a raw token and as an id from `list`.", file=sys.stderr)
        sys.exit(1)


def cmd_migrate(args):
    path = token_store.TOKENS_PATH

    if not os.path.exists(path):
        print(f"No tokens.json at {path} yet — nothing to migrate.")
        return

    with open(path, "r") as f:
        content = f.read().strip()
        raw = json.loads(content) if content else {}

    if raw.get("version") == token_store._FORMAT_VERSION and isinstance(raw.get("tokens"), dict):
        print(f"{path} is already on format version {token_store._FORMAT_VERSION} "
              f"({len(raw['tokens'])} token(s)). Nothing to do.")
        return

    if "version" in raw:
        print(f"{path} has an unrecognized format version {raw.get('version')!r} — refusing to touch it.", file=sys.stderr)
        sys.exit(1)

    original_tokens = dict(raw)
    count = len(original_tokens)
    if count == 0:
        print(f"{path} exists but has no tokens yet — nothing to migrate.")
        return

    print(f"Found {count} token(s) in the old (unhashed) format at {path}.")
    print("Migrating will hash every token in place; the raw values will no")
    print("longer be recoverable from this file afterward.")
    print()

    if not args.yes:
        answer = input("Proceed with migration now? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Aborted — nothing was changed.")
            return

    token_store.list_tokens()

    failures = [t for t in original_tokens if token_store.get_record(t) is None]
    if failures:
        print(f"VERIFICATION FAILED: {len(failures)} of {count} token(s) no longer resolve "
              "after migration.", file=sys.stderr)
        print("Do not deploy this file. Restore your backup if you made one, "
              "and please report this.", file=sys.stderr)
        sys.exit(1)

    with open(path, "r") as f:
        after = json.load(f)

    print(f"Migrated and verified {count} token(s): every original token was re-checked")
    print("against the new file and still resolves to the correct record.")
    print(f"{path} is now format version {after.get('version')} with {len(after.get('tokens', {}))} entries.")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create", help="Create a pair of identical, unbound access tokens for one person (one main, one for their decoy vault)")
    p_create.add_argument("--label", help="A human-readable note (e.g. a name) — not sent to clients")
    p_create.add_argument("--quota-gb", type=float, help=f"Storage quota in GB (default: {token_store.DEFAULT_QUOTA_BYTES / 1024**3:g})")
    p_create.set_defaults(func=cmd_create)

    p_strip = sub.add_parser("strip-decoy-labels", help="Remove the '(decoy)' marker older versions added to decoy tokens' labels")
    p_strip.set_defaults(func=cmd_strip_decoy_labels)

    p_list = sub.add_parser("list", help="List all tokens and their status")
    p_list.set_defaults(func=cmd_list)

    p_revoke = sub.add_parser("revoke", help="Delete a token, blocking further uploads with it")
    p_revoke.add_argument("token", help="The raw token from `create`, or the short id shown by `list`")
    p_revoke.set_defaults(func=cmd_revoke)

    p_migrate = sub.add_parser("migrate", help="Migrate tokens.json to hashed storage now, with verification (safe to run anytime — no-ops if already migrated)")
    p_migrate.add_argument("--yes", action="store_true", help="Don't prompt for confirmation")
    p_migrate.set_defaults(func=cmd_migrate)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()