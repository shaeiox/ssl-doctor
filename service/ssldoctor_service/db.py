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


def migrate(admin_dsn: str, upto: Optional[str] = None) -> list:
    """Apply pending migrations in order (optionally only through `upto`).

    Returns the names applied. `upto` supports staged upgrades and tests that
    reproduce an older schema state.
    """
    applied = []
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS public.schema_migrations "
                     "(name text PRIMARY KEY, applied_at timestamptz DEFAULT now())")
        done = {r[0] for r in conn.execute("SELECT name FROM public.schema_migrations")}
        for name in sorted(f for f in os.listdir(MIGRATIONS_DIR) if f.endswith(".sql")):
            if upto and name > upto:
                break
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


def bootstrap_org(admin_dsn: str, name: str, token: str, role: str = "owner",
                  slug: Optional[str] = None, email: Optional[str] = None) -> UUID:
    """Create an organization, its first user and that user's API token."""
    import re
    import uuid as _uuid
    slug = slug or (re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "org") \
        + "-" + _uuid.uuid4().hex[:6]
    with psycopg.connect(admin_dsn) as conn:
        org_id = conn.execute("INSERT INTO app.organizations (name, slug) VALUES (%s, %s) "
                              "RETURNING id", (name, slug)).fetchone()[0]
        user_id = conn.execute("INSERT INTO app.users (org_id, email, role) VALUES "
                               "(%s, %s, %s) RETURNING id",
                               (org_id, email or f"{role}@{slug}.local", role)).fetchone()[0]
        conn.execute("INSERT INTO app.api_tokens (org_id, name, token_hash, role, user_id) "
                     "VALUES (%s, 'bootstrap', %s, %s, %s)",
                     (org_id, sha256_hex(token), role, user_id))
    return org_id


def add_user_with_token(admin_dsn: str, org_id: UUID, email: str, role: str,
                        token: str) -> UUID:
    """Admin helper (install scripts, tests): a user plus one API token."""
    with psycopg.connect(admin_dsn) as conn:
        user_id = conn.execute("INSERT INTO app.users (org_id, email, role) VALUES "
                               "(%s, %s, %s) RETURNING id", (org_id, email, role)).fetchone()[0]
        conn.execute("INSERT INTO app.api_tokens (org_id, name, token_hash, role, user_id) "
                     "VALUES (%s, %s, %s, %s, %s)",
                     (org_id, role, sha256_hex(token), role, user_id))
    return user_id


def connect_info(dsn: str, **overrides: Optional[str]) -> str:
    """Return `dsn` with conninfo keys overridden (e.g. user=ssldoctor_app)."""
    params = psycopg.conninfo.conninfo_to_dict(dsn)
    params.update({k: v for k, v in overrides.items() if v is not None})
    return psycopg.conninfo.make_conninfo(**params)
