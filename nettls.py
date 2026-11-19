"""TLS settings for web lookups. Certificate checking is always on.

On Windows, Python only trusts root certificates that Windows has already downloaded, so a site
whose root Windows hasn't fetched yet fails with CERTIFICATE_VERIFY_FAILED even though it's fine
(seen with urlhaus-api.abuse.ch). certifi's standard list of trusted roots (installed with the
Desk) avoids that; without it, the system's list is used.
"""
import ssl


def context():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()
