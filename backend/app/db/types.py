"""Cross-dialect column types.

Production uses Postgres (JSONB, native UUID), but the fast unit tests
run on in-memory SQLite. `.with_variant(...)` lets the same models
generate correct DDL on both.
"""

from sqlalchemy import JSON
from sqlalchemy import Uuid as _Uuid
from sqlalchemy.dialects.postgresql import JSONB

# Native UUID on Postgres, CHAR(32) representation elsewhere.
GUID = _Uuid(as_uuid=True)

# JSONB on Postgres, plain JSON (TEXT-backed) on SQLite / other dialects.
JSONVariant = JSONB().with_variant(JSON(), "sqlite")
