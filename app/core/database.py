import uuid

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def set_rls_context(db: Session, user_id: uuid.UUID | None, role: str = "user") -> None:
    """User Scan Ownership: الـ PostgreSQL RLS policies بتعتمد على الـ GUCs دي.
    SQLite (dev) بيتجاهلها والفلترة بتتم في الـ queries."""
    if engine.dialect.name == "postgresql":
        db.execute(text("SELECT set_config('app.current_user', :u, true)"),
                   {"u": str(user_id) if user_id else ""})
        db.execute(text("SELECT set_config('app.current_role', :r, true)"), {"r": role})


if engine.dialect.name == "sqlite":
    # pragmas معقولة للـ dev
    @event.listens_for(engine, "connect")
    def _sqlite_pragma(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
