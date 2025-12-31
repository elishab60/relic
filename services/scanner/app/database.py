from sqlmodel import SQLModel, create_engine, Session
from sqlalchemy import text
import logging

logger = logging.getLogger(__name__)

sqlite_file_name = "auditai.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, echo=False, connect_args=connect_args)


def run_migrations():
    """
    Run any necessary database migrations.
    This is called after create_db_and_tables to handle schema changes.
    """
    with engine.connect() as conn:
        # Check if config_json column exists in scan table
        result = conn.execute(text("PRAGMA table_info(scan)"))
        columns = [row[1] for row in result.fetchall()]
        
        # PR-02a: Add config_json column if it doesn't exist
        if "config_json" not in columns:
            logger.info("Migrating database: Adding config_json column to scan table")
            try:
                conn.execute(text("ALTER TABLE scan ADD COLUMN config_json TEXT"))
                conn.commit()
                logger.info("Migration complete: config_json column added")
            except Exception as e:
                logger.error(f"Migration failed: {e}")
                raise


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)
    # Run migrations after table creation
    run_migrations()


def get_session():
    with Session(engine) as session:
        yield session

