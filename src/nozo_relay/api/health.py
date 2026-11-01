from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import text

from nozo_relay.api.deps import DbDep
from nozo_relay.api.errors import RelayError
from nozo_relay.db.schema import SCHEMA_VERSION, SchemaError, check_sqlite_runtime, read_schema_version

router = APIRouter(prefix="/api/v1/health", tags=["health"])


@router.get("/live")
def live() -> dict[str, str]:
    """Process is up. No dependencies, no sensitive detail."""
    return {"status": "live"}


@router.get("/ready")
def ready(db: DbDep) -> dict[str, object]:
    """DB reachable, schema version compatible, SQLite runtime acceptable."""
    try:
        db.execute(text("SELECT 1")).scalar_one()
        engine = db.get_bind()
        found = read_schema_version(engine)  # type: ignore[arg-type]
        check_sqlite_runtime()
    except SchemaError:
        raise RelayError(503, "not_ready", "Database runtime not compatible", retryable=False) from None
    except Exception:
        raise RelayError(503, "not_ready", "Database unavailable", retryable=True) from None
    if found != SCHEMA_VERSION:
        raise RelayError(503, "not_ready", "Schema version incompatible", retryable=False)
    return {"status": "ready", "db": "ok", "schema_version": found}
