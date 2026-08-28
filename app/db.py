import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

REQUIRED_TABLES = (
    "incidents",
    "incident_steps",
    "remediation_log",
    "service_catalog",
    "approvals",
    "scorecards",
    "scorecard_results",
    "audit_log",
)


def postgres_conninfo() -> str:
    password = os.environ.get("PGPASSWORD", "")
    parts = {
        "host": os.environ.get("PGHOST", "postgres"),
        "port": os.environ.get("PGPORT", "5432"),
        "dbname": os.environ.get("PGDATABASE", "postgres"),
        "user": os.environ.get("PGUSER", "postgres"),
        "password": password,
    }
    return " ".join(f"{key}={value}" for key, value in parts.items())


@asynccontextmanager
async def create_pool() -> AsyncIterator[AsyncConnectionPool]:
    pool = AsyncConnectionPool(
        conninfo=postgres_conninfo(),
        kwargs={"row_factory": dict_row},
        min_size=1,
        max_size=int(os.environ.get("DB_POOL_MAX_SIZE", "5")),
        open=False,
    )
    await pool.open(wait=False)
    try:
        yield pool
    finally:
        await pool.close()
