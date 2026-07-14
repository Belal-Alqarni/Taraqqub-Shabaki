from functools import lru_cache
from os import getenv


class Settings:
    def __init__(self) -> None:
        self.db_path = getenv("TARAQQUB_DB_PATH", "./data/taraqqub.db")
        self.database_url = getenv("TARAQQUB_DATABASE_URL", "").strip() or None
        self.monitor_interval = int(getenv("TARAQQUB_MONITOR_INTERVAL", "10"))
        self.enable_self_healing = getenv("TARAQQUB_ENABLE_SELF_HEALING", "false").lower() == "true"
        self.app_env = getenv("TARAQQUB_ENV", "development").lower()
        self.admin_username = getenv("TARAQQUB_ADMIN_USERNAME", "admin")
        self.admin_password = getenv("TARAQQUB_ADMIN_PASSWORD", "Taraqqub!2026")
        self.session_hours = int(getenv("TARAQQUB_SESSION_HOURS", "12"))
        secure_default = "true" if self.app_env == "production" else "false"
        self.secure_cookies = (
            getenv("TARAQQUB_SECURE_COOKIES", secure_default).lower() == "true"
        )
        self.scan_network = getenv("TARAQQUB_SCAN_NETWORK", "").strip() or None
        self.scan_gateway = getenv("TARAQQUB_SCAN_GATEWAY", "").strip() or None
        self.public_demo = getenv("TARAQQUB_PUBLIC_DEMO", "false").lower() == "true"
        self.allow_signup = getenv("TARAQQUB_ALLOW_SIGNUP", "false").lower() == "true"


@lru_cache
def get_settings() -> Settings:
    return Settings()
