import socket
import ssl
from urllib.parse import urlparse

def get_certificate_field(data, field_name):
    for item in data:
        for field in item:
            if field[0] == field_name:
                return field[1]

    return "Unknown"

def get_ssl_info(url):
    parsed = urlparse(url)
    hostname = parsed.hostname

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((hostname, 443))

    context = ssl.create_default_context()

    ssl_sock = context.wrap_socket(
        sock,
        server_hostname=hostname
    )

    certificate = ssl_sock.getpeercert()

    subject = get_certificate_field(
         certificate["subject"],
         "commonName"
    )
    issuer = get_certificate_field(
        certificate["issuer"],
        "organizationName"
    )
    valid_from = certificate.get("notBefore")
    valid_until = certificate.get("notAfter")

    ssl_sock.close()

    return {
       "subject": subject,
       "issuer": issuer,
       "valid_from": valid_from,
       "valid_until": valid_until
    }
