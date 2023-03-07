# DRF Access Key
A library that provides a simple Access Key &amp; Secret Key authorization for Django REST framework.

## Requirements
* Python 3.6+
* Django 2.X+
* Django REST Framework 3.X+

## Install
```shell
pip install git+https://github.com/ZhaoQi99/drf-access-key.git
or
pip install drf-access-key #TODO
✨🍰✨
```
## Quick Start

1. Add `rest_framework_access_key` to your `INSTALLED_APPS` setting:

```python
INSTALLED_APPS = [
    ...,
    'rest_framework_access_key',
]
```
2. Add `AccessKeyAuthentication` to your DEFAULT_AUTHENTICATION_CLASSES located at settings.py from your project:

```py
REST_FRAMEWORK = {
    ...,
    'DEFAULT_AUTHENTICATION_CLASSES': (
        ...,
      	'rest_framework_access_key.authentication.AccessKeyAuthentication',
    ),
}
```

## How to use

```apl
GET /api/v1/user/ HTTP/1.1
Auth-Access-Key: XXXXXXXX
Auth-Nonce: 83a1ca5507564efd891ad8d6e04529ee
Auth-Timestamp: 1677636324
Content-Type: application/json
Auth-Signature: XXXXXXX
```

## Settings

Settings are configurable in `settings.py` in the scope `ACCESS_KEY_DEFAULTS`. You can override any setting, otherwise the defaults below are used.

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