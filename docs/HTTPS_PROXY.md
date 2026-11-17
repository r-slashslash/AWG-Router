# HTTPS proxy clients

Clients can also be configured as HTTP proxies for applications that do not
support TLS to the proxy. HTTP sends proxy credentials without encryption: use
it only over a protected VPN or SSH tunnel. HTTPS destinations remain encrypted
end to end. Existing proxy clients default to HTTPS.

The proxy URL uses `https://`, so TLS protects the proxy credentials in transit.
Each proxy client has its own username, password, port and exit. A disabled client
cannot open a new connection and active connections are closed. If the selected
exit is unavailable, traffic is blocked rather than sent directly.

The proxy supports HTTPS destinations via CONNECT and HTTP destinations with a
fixed Content-Length body up to 64 MiB. Chunked request bodies, HTTP upgrades and
IPv6 destination addresses are not supported. TLS certificates are shared with
the panel and updated by the panel's certificate manager.

## Python requests

Use `requests` with **urllib3 2.8 or newer** and explicitly configure a TLS
context for the proxy. A test with urllib3 2.7 showed that the proxy certificate
could remain unverified for an HTTP destination even with a supplied context.
The tests check both trusted and untrusted proxy certificates. Other libraries
and versions need their own compatibility checks.

```python
import os
import ssl
import requests

class VerifiedProxyAdapter(requests.adapters.HTTPAdapter):
    def proxy_manager_for(self, proxy_url, **kwargs):
        kwargs["proxy_ssl_context"] = ssl.create_default_context()
        return super().proxy_manager_for(proxy_url, **kwargs)

proxy_url = os.environ["AWGR_PROXY_URL"]  # https://user:password@host:port
with requests.Session() as session:
    session.trust_env = False
    session.mount("http://", VerifiedProxyAdapter())
    session.mount("https://", VerifiedProxyAdapter())
    response = session.get("https://example.com/", proxies={"https": proxy_url}, timeout=15)
    response.raise_for_status()
```

Store credentials outside source code and version control. Configure HTTPS and
HTTP proxy settings separately if both are needed. Neither the URL scheme nor
a successful TLS handshake alone proves that a particular HTTP client verifies
the proxy certificate; test this with an untrusted certificate before use.
