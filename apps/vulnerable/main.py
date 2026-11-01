from apps.core.application import create_app
from apps.core.config import Settings
from apps.vulnerable.policy import TrainingPolicy

app = create_app(TrainingPolicy(), Settings(origin="http://127.0.0.1:18080"))
