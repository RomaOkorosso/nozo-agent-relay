"""CLI: ``python -m nozo_relay {serve,bootstrap,check}``."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from nozo_relay.bootstrap import BootstrapError, bootstrap
from nozo_relay.config import Settings, SettingsError


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nozo-relay", description="Nozo Agent Relay")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("serve", help="run the API on the configured loopback address (default)")
    b = sub.add_parser("bootstrap", help="one-time owner/agent/project bootstrap")
    b.add_argument("--username", default="owner")
    b.add_argument(
        "--prompt-password",
        action="store_true",
        help="read the owner password from the terminal (otherwise one is generated)",
    )
    sub.add_parser("check", help="validate settings, SQLite runtime and schema, then exit")
    bk = sub.add_parser("backup", help="online SQLite backup + artifacts + manifest into a NEW directory")
    bk.add_argument("--to", required=True, help="empty or non-existent destination directory")
    vb = sub.add_parser("verify-backup", help="verify a backup directory against its manifest (read-only)")
    vb.add_argument("--from", dest="src", required=True)
    rs = sub.add_parser("restore", help="restore a backup into a NEW data directory (never overwrites)")
    rs.add_argument("--from", dest="src", required=True, help="backup directory")
    rs.add_argument("--to-data-dir", required=True, help="empty or non-existent data directory")
    rs.add_argument("--migrate", action="store_true", help="upgrade a v2 backup COPY to the current schema")
    sub.add_parser("migrate", help="back up, then upgrade a v2/v3 database in place (server must be stopped)")
    rb = sub.add_parser("repo-bind", help="OWNER ONLY: register the canonical git repository of a project (never via API)")
    rb.add_argument("--project", required=True, help="project slug or id")
    rb.add_argument("--root", required=True, help="absolute path of the canonical repository")
    ra = sub.add_parser("repo-approve-dirty", help="OWNER ONLY: save the CURRENT dirty tree of a binding as the baseline")
    ra.add_argument("--binding", required=True)
    rq = sub.add_parser("repo-clear-quarantine", help="OWNER ONLY: clear the quarantine of a binding after inspection")
    rq.add_argument("--binding", required=True)
    sub.add_parser("sandbox-probe", help="run the sandbox/cgroup capability probe and print the report (no relay access needed)")
    mk = sub.add_parser("mint-key", help="OWNER ONLY: mint a key for a registered non-owner agent (e.g. coordinator); written once to a 0600 file, never printed")
    mk.add_argument("--agent", required=True, help="principal id or exact display name (owner principals are refused)")
    mk.add_argument("--expires-in-days", type=int, default=None, help="optional key lifetime (default: until revoked)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    cmd = args.cmd or "serve"
    try:
        settings = Settings()
        if cmd == "serve":
            from nozo_relay.main import serve

            serve(settings)
            return 0
        if cmd == "bootstrap":
            password = None
            if args.prompt_password:
                password = getpass.getpass("Owner password (min 12 chars): ")
                if password != getpass.getpass("Repeat: "):
                    print("passwords differ", file=sys.stderr)
                    return 2
            result = bootstrap(settings, owner_username=args.username, owner_password=password)
            print(f"Bootstrap complete. Credentials written once to: {result.credentials_path}")
            print("Copy them to a private store and delete the file. Secrets are not printed.")
            return 0
        if cmd == "check":
            from nozo_relay.main import create_app

            create_app(settings)
            print("ok")
            return 0
        if cmd == "backup":
            from nozo_relay.backup import create_backup

            manifest = create_backup(settings, Path(args.to))
            print(f"Backup written to {args.to} (schema v{manifest['schema_version']}, "
                  f"{len(manifest['artifacts'])} artifact(s), last event seq {manifest['last_event_seq']}).")
            for problem in manifest["problems"]:
                print(f"warning: {problem}", file=sys.stderr)
            return 0 if manifest["complete"] else 3
        if cmd == "verify-backup":
            from nozo_relay.backup import verify_backup

            manifest = verify_backup(Path(args.src))
            print(f"ok: backup of {manifest['created_at_rfc3339']} (schema v{manifest['schema_version']})")
            return 0
        if cmd == "restore":
            from nozo_relay.backup import restore_backup

            report = restore_backup(Path(args.src), Path(args.to_data_dir), migrate=args.migrate)
            print(f"Restored into {report['target']}: sessions revoked={report['sessions_revoked']}, "
                  f"active runs fenced={report['runs_lost']}. Start with NOZO_RELAY_DATA_DIR={report['target']}")
            return 0
        if cmd == "migrate":
            import time

            from nozo_relay.backup import create_backup
            from nozo_relay.db.engine import create_engine_from_settings
            from nozo_relay.db.schema import migrate_to_current

            dest = settings.data_dir / "backups" / f"pre-migrate-{int(time.time())}"
            create_backup(settings, dest)
            engine = create_engine_from_settings(settings)
            try:
                before, after = migrate_to_current(engine)
            finally:
                engine.dispose()
            print(f"Schema v{before} -> v{after} (backup: {dest})")
            return 0
        if cmd in ("repo-bind", "repo-approve-dirty", "repo-clear-quarantine"):
            from nozo_relay.clock import SystemClock
            from nozo_relay.db.engine import create_engine_from_settings, write_session
            from nozo_relay.services import repo_bindings as rb_svc

            engine = create_engine_from_settings(settings)
            try:
                with write_session(engine) as ws:
                    if cmd == "repo-bind":
                        b = rb_svc.register_binding(ws, SystemClock(), project=args.project, canonical_root=args.root,
                                                    protected_dirs=[settings.data_dir])
                        print(f"Bound project {args.project} -> {b.canonical_root} (binding {b.id}, identity {b.repo_identity})")
                    elif cmd == "repo-approve-dirty":
                        tree = rb_svc.approve_dirty_snapshot(ws, SystemClock(), binding_id=args.binding)
                        print(f"Saved the current dirty tree as the baseline (tree_hash {tree}). It stops matching as soon as the tree changes.")
                    else:
                        rb_svc.clear_quarantine(ws, binding_id=args.binding)
                        print("Quarantine cleared.")
            finally:
                engine.dispose()
            return 0
        if cmd == "mint-key":
            from nozo_relay.keymint import mint_key

            res = mint_key(settings, args.agent, expires_in_days=args.expires_in_days)
            print(f"Key for {res.kind} {res.principal_id} (credential {res.credential_id}) written once to: {res.path}")
            print("The key is NOT printed. Copy it to a private store and delete the file; revoke via POST /api/v1/agents/{id}/keys/{key_id}/revoke.")
            return 0
        if cmd == "sandbox-probe":
            import json as _json

            from nozo_relay.runner.supervisor import Supervisor, SupervisorConfig
            from nozo_relay.services.repo_bindings import StaticBindingRegistry

            caps = Supervisor(SupervisorConfig(state_dir=settings.runner_state_dir), {}, StaticBindingRegistry()).probe(force=True)
            print(_json.dumps(caps.to_dict(), indent=2, sort_keys=True))
            return 0 if caps.verdict == "probe_pass" else 3
    except (BootstrapError, SettingsError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
