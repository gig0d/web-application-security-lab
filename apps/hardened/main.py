from apps.core.application import create_app
from apps.core.security import SecurePolicy

app = create_app(SecurePolicy())
