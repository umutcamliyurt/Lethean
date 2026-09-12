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
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def run_migrations() -> None:
    inspector = inspect(engine)
    if "share_tokens" not in inspector.get_table_names():
        return

    existing_columns = {c["name"] for c in inspector.get_columns("share_tokens")}
    if "delete_token_hash" in existing_columns:
        return

    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE share_tokens ADD COLUMN delete_token_hash VARCHAR"))
        conn.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS ix_share_tokens_delete_token_hash "
            "ON share_tokens (delete_token_hash)"
        ))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()