from alembic import command
from alembic.config import Config
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from apps.core.config import Settings
from apps.core.database import make_engine
from apps.core.models import Attachment, Ticket, User
from apps.core.seed import seed


def main() -> None:
    command.upgrade(Config("alembic.ini"), "head")
    engine = make_engine(Settings().database_url)
    with Session(engine) as db:
        seed(db)
        if engine.dialect.name == "postgresql":
            # Runtime principal cannot create/drop tables, change roles, or own objects.
            db.execute(text("GRANT USAGE ON SCHEMA public TO aegis_app"))
            db.execute(
                text(
                    "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aegis_app"
                )
            )
            db.execute(text("REVOKE ALL ON TABLE alembic_version FROM aegis_app"))
            db.execute(text("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO aegis_app"))
            # Explicit fixture IDs must advance PostgreSQL identity sequences.
            for model in (User, Ticket, Attachment):
                maximum = db.scalar(select(func.max(model.id))) or 1
                db.execute(
                    text("SELECT setval(pg_get_serial_sequence(:table, 'id'), :value)"),
                    {"table": model.__tablename__, "value": maximum},
                )
            db.commit()
    engine.dispose()


if __name__ == "__main__":
    main()
