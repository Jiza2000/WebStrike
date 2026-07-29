from urllib.parse import urlparse
import socket


def validate_target(url):
    """
    Validate and normalize the target URL.
    """

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.netloc:
        raise ValueError("Invalid URL")

    return url


def resolve_ip(url):
    """
    Resolve the domain name to an IP address.
    """

    hostname = urlparse(url).hostname
    return socket.gethostbyname(hostname)
