from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = "sqlite:///./lethean.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    pool_size=30,
    max_overflow=60,
    pool_timeout=30,
)


@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA busy_timeout=30000")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA temp_store=MEMORY")
    cursor.execute("PRAGMA cache_size=-65536")
    cursor.execute("PRAGMA mmap_size=268435456")
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def run_migrations() -> None:
    inspector = inspect(engine)
    tables = inspector.get_table_names()

    if "share_tokens" in tables:
        existing_columns = {c["name"] for c in inspector.get_columns("share_tokens")}
        if "delete_token_hash" not in existing_columns:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE share_tokens ADD COLUMN delete_token_hash VARCHAR"))
                conn.execute(text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS ix_share_tokens_delete_token_hash "
                    "ON share_tokens (delete_token_hash)"
                ))

    if "files" in tables:
        with engine.begin() as conn:
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_files_vault_listing ON files (vault_id, created_at DESC, id)"
            ))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_files_vault_size ON files (vault_id, size)"))
            conn.execute(text("DROP INDEX IF EXISTS ix_files_vault_created"))
            conn.execute(text("ANALYZE files"))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()