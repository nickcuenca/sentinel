from app.db.base_class import Base

# Import all models so Alembic autogenerate can find them
from app.models.user import User  # noqa: F401
from app.models.secret import Secret  # noqa: F401
from app.models.audit import AuditLog  # noqa: F401