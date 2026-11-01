from apps.core.application import create_app
from apps.core.config import Settings
from apps.vulnerable.policy import TrainingPolicy


class TrainingSettings(Settings):
    database_url: str = "sqlite:///./.runtime/vulnerable.db"
    origin: str = "http://127.0.0.1:18080"


app = create_app(TrainingPolicy(), TrainingSettings())
