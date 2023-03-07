from typing import Any, Dict
from rest_framework.settings import APISettings
from django.conf import settings

ACCESS_KEY_DEFAULTS: Dict[str, Any] = {
    "NONCE_CACHE_PREFIX": "OpenAPI",
    "NONCE_CACHE_TTL": 5,
    "TIMESTAMP_ERROR_RANGE": 10 * 60,
}

access_key_settings = APISettings(
    user_settings=getattr(settings, "ACCESS_KEY_SETTINGS", {}),
    defaults=ACCESS_KEY_DEFAULTS,
)
