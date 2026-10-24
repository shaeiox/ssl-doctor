"""Database access: forward-only migrations and tenant-scoped transactions.

Every request touching tenant data runs inside ``Database.org(org_id)``,
which sets ``app.org_id`` for that transaction only. Row-level security then
filters every query, so a missing WHERE clause can't leak another tenant's
rows.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
from typing import Iterator, Optional
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

MIGRATIONS_DIR = os.path.join(os.path.dirname(__file__), "migrations")


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def migrate(admin_dsn: str) -> list:
    """Apply pending migrations in order. Returns the names applied."""
    applied = []
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS public.schema_migrations "
                     "(name text PRIMARY KEY, applied_at timestamptz DEFAULT now())")
        done = {r[0] for r in conn.execute("SELECT name FROM public.schema_migrations")}
        for name in sorted(f for f in os.listdir(MIGRATIONS_DIR) if f.endswith(".sql")):
            if name in done:
                continue
            with open(os.path.join(MIGRATIONS_DIR, name), encoding="utf-8") as fh:
                sql = fh.read()
            with conn.transaction():
                conn.execute(sql)
                conn.execute("INSERT INTO public.schema_migrations (name) VALUES (%s)",
                             (name,))
            applied.append(name)
    return applied


class Database:
    """Connection factory for the application role (subject to RLS)."""

    def __init__(self, app_dsn: str) -> None:
        self.app_dsn = app_dsn

    @contextlib.contextmanager
    def system(self) -> Iterator[psycopg.Connection]:
        """No tenant set: only SECURITY DEFINER auth functions return data."""
        with psycopg.connect(self.app_dsn, row_factory=dict_row) as conn:
            yield conn

    @contextlib.contextmanager
    def org(self, org_id: UUID) -> Iterator[psycopg.Connection]:
        with psycopg.connect(self.app_dsn, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('app.org_id', %s, true)", (str(org_id),))
                yield conn


def bootstrap_org(admin_dsn: str, name: str, token: str,
                  role: str = "owner") -> UUID:
    """Create an organization and its first API token (installation/admin task)."""
    with psycopg.connect(admin_dsn) as conn:
        org_id = conn.execute("INSERT INTO app.organizations (name) VALUES (%s) "
                              "RETURNING id", (name,)).fetchone()[0]
        conn.execute("INSERT INTO app.api_tokens (org_id, name, token_hash, role) "
                     "VALUES (%s, 'bootstrap', %s, %s)", (org_id, sha256_hex(token), role))
    return org_id


def connect_info(dsn: str, **overrides: Optional[str]) -> str:
    """Return `dsn` with conninfo keys overridden (e.g. user=ssldoctor_app)."""
    params = psycopg.conninfo.conninfo_to_dict(dsn)
    params.update({k: v for k, v in overrides.items() if v is not None})
    return psycopg.conninfo.make_conninfo(**params)
