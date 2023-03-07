# DRF Access Key
A library that provides a simple Access Key &amp; Secret Key authorization for Django REST framework.

## Requirements
* Python 3.6+
* [Django](https://docs.djangoproject.com/) 2.X+
* [Django REST framework](https://www.django-rest-framework.org/) 3.X+

## Install
```shell
pip install git+https://github.com/ZhaoQi99/drf-access-key.git
or
pip install drf-access-key #TODO
✨🍰✨
```
## Quick Start

1. Add `rest_framework_access_key` to `INSTALLED_APPS` setting:

```python
INSTALLED_APPS = [
    ...,
    'rest_framework_access_key',
]
```
2. Add `AccessKeyAuthentication` to `DEFAULT_AUTHENTICATION_CLASSES` setting located at settings.py from your project:

```python
REST_FRAMEWORK = {
    ...,
    'DEFAULT_AUTHENTICATION_CLASSES': (
        ...,
      	'rest_framework_access_key.authentication.AccessKeyAuthentication',
    ),
}
```

3. Custom `authentication_classes` in [Django REST framework](https://www.django-rest-framework.org/) APIView:

```python
from rest_framework import generics,permissions
from rest_framework.response import Response

from rest_framework_access_key.authentication import AccessKeyAuthentication

class TestViewSet(generics.GenericAPIView):
    authentication_classes = (AccessKeyAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        return Response({"Hello": "World!"})

```

## How to use

[Authentication Method Document 🇨🇳](docs/auth.md) 

```ini
GET /api/v1/user/ HTTP/1.1
Auth-Access-Key: XXXXXXXX
Auth-Nonce: 83a1ca5507564efd891ad8d6e04529ee
Auth-Timestamp: 1677636324
Content-Type: application/json
Auth-Signature: XXXXXXX
```

## Settings

Settings are configurable in `settings.py` in the scope `ACCESS_KEY_SETTINGS`. You can override any setting, otherwise the defaults below are used.

```python
ACCESS_KEY_DEFAULTS: Dict[str, Any] = {
    "NONCE_CACHE_PREFIX": "OpenAPI",
    "NONCE_CACHE_TTL": 5,
    "TIMESTAMP_ERROR_RANGE": 10 * 60,
}
```


## License

[GNU General Public License v3.0](https://github.com/ZhaoQi99/drf-access-key/blob/main/LICENSE)

## Author

* Qi Zhao([zhaoqi99@outlook.com](mailto:zhaoqi99@outlook.com))