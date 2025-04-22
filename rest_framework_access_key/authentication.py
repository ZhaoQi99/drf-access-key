import base64
import hashlib
import hmac
import json
from datetime import timedelta

from django.core.cache import cache
from django.utils import timezone
from rest_framework import authentication
from rest_framework.exceptions import (
    AuthenticationFailed,
    PermissionDenied,
    ValidationError,
)

from .models import OpenAPIAuth
from .settings import access_key_settings

AUTH_HEADER = "Auth-Access-Key"
NONCE_HEADER = "Auth-Nonce"
TIMESTAMP_HEADER = "Auth-Timestamp"
SIGNATURE_HEADER = "Auth-Signature"

SIGNED_HEADERS = (AUTH_HEADER, NONCE_HEADER, TIMESTAMP_HEADER)

VALIDATE_HEADERS = (NONCE_HEADER, TIMESTAMP_HEADER, SIGNATURE_HEADER)


class Signer:
    """
    StringToSign:
        HTTPMethod
        Content-MD5
        Headers
        PathAndParameters
    """

    def __init__(self, request) -> None:
        self._request = request

    def get_string_to_sign(self):
        signed_tuple = (
            self._request.method.upper(),
            self.get_content_md5(),
            self.get_signed_headers(),
            self.get_path_and_params(),
        )
        return "\n".join(signed_tuple)

    def get_signature(self, secret_key):
        return self._sign(self.get_string_to_sign(), secret_key)

    def get_content_md5(self):
        body = self._request.data

        if not body:
            return ""

        body_str = json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
        return base64.b64encode(hashlib.md5(body_str).digest()).decode()

    def get_signed_headers(self):
        headers = self._request.headers
        return "\n".join(
            [f"{header}:{headers.get(header, '')}" for header in sorted(SIGNED_HEADERS)]
        )

    def get_path_and_params(self):
        path = self._request.path
        params = self._request.GET.dict()
        if params:
            return "%s?%s" % (path, self.tuple2str(sorted(params.items())))
        return path

    def _sign(self, raw_str: str, secret_key: str):
        return base64.b64encode(
            hmac.new(
                secret_key.encode(), raw_str.encode(), digestmod=hashlib.sha256
            ).digest()
        ).decode()

    def tuple2str(self, t):
        return "&".join(["=".join(item) for item in t])

class AccessKey:
    is_authenticated = True

    def __init__(self, access_key, auth=None):
        self.access_key = access_key
        self.auth = auth

    def __str__(self) -> str:
        return "AccessKey: {}".format(self.access_key)

class AccessKeyAuthentication(authentication.BaseAuthentication):
    """
    Headers:
        Auth-Access-Key: xx
        Auth-Nonce: xx
        Auth-Signature: xx
        Auth-Timestamp: xx
    """

    www_authenticate_realm = "api"
    nonce_cache_prefix = access_key_settings.NONCE_CACHE_PREFIX
    nonce_cache_ttl = access_key_settings.NONCE_CACHE_TTL
    error_range = access_key_settings.TIMESTAMP_ERROR_RANGE

    def authenticate(self, request):
        headers = request.headers
        access_key = headers.get(AUTH_HEADER, None)
        if not access_key:
            return None
        self.validate(request)
        obj = OpenAPIAuth.objects.filter(access_key=access_key).first()
        if not obj:
            raise PermissionDenied(f"Access key {access_key} not exists.")
        if obj.enable is False:
            raise PermissionDenied(f"Access key {access_key} is disable.")
        if obj.is_expired:
            raise PermissionDenied("Access key {access_key} has already expired.")

        secret_key = obj.secret_key
        signature = headers.get(SIGNATURE_HEADER, "")

        sign = Signer(request)
        real_signature = sign.get_signature(secret_key)
        if signature != real_signature:
            raise AuthenticationFailed(
                "Invalid Signature,StringToSign: %s" % sign.get_string_to_sign()
            )
        return AccessKey(access_key, obj), None

    def authenticate_header(self, request):
        return '{} realm="{}"'.format(AUTH_HEADER, self.www_authenticate_realm)

    def validate(self, request):
        headers = request.headers
        self.validate_header(headers)
        self.validate_timestamp(headers.get(TIMESTAMP_HEADER, ""))
        self.validate_nonce(headers.get(NONCE_HEADER, ""))

    def validate_header(self, headers):
        for header in VALIDATE_HEADERS:
            if header not in headers.keys():
                raise ValidationError({"detail": "%s header is required." % header})
            value = headers.get(header, None)
            if not value:
                raise ValidationError({"detail": "%s value can't be empty." % header})

    def validate_timestamp(self, timestamp):
        timestamp = int(timestamp)
        current_time = int(timezone.now().timestamp())
        if (
            abs(current_time - timestamp)
            > timedelta(seconds=self.error_range).total_seconds()
        ):
            raise PermissionDenied("Auth-Timestamp is invalid.")

    def validate_nonce(self, nonce):
        key = "{}-{}".format(self.nonce_cache_prefix, nonce)
        if cache.get(key, None) is not None:
            raise PermissionDenied("Specified nonce was used already.")
        else:
            cache.set(key, "1", self.nonce_cache_ttl)
