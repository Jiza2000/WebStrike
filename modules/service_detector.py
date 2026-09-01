import socket
import ssl


def detect_service(ip, port, hostname=None):
    try:
        sock = socket.socket()
        sock.settimeout(3)

        sock.connect((ip, port))

        if port == 443:
            context = ssl._create_unverified_context()

            ssl_sock = context.wrap_socket(
                sock,
                server_hostname=hostname or ip
            )

            request = (
                "HEAD / HTTP/1.1\r\n"
                f"Host: {hostname or ip}\r\n"
                "Connection: close\r\n"
                "\r\n"
            )

            ssl_sock.send(request.encode())

            response = ssl_sock.recv(1024).decode(
                errors="ignore"
            )

            ssl_sock.close()

            return response

        elif port == 80:
            request = (
                "HEAD / HTTP/1.1\r\n"
                f"Host: {hostname or ip}\r\n"
                "Connection: close\r\n"
                "\r\n"
            )

            sock.send(request.encode())

            response = sock.recv(1024).decode(
                errors="ignore"
            )

            sock.close()

            return response

        else:
            banner = sock.recv(1024).decode(
                errors="ignore"
            )

            sock.close()

            return banner.strip()

    except Exception:
        return "Unknown"


def parse_http_banner(response, service="HTTP"):
    lines = response.splitlines()

    status = "Unknown"
    server = "Unknown"
    version = "Unknown"

    if lines:
        parts = lines[0].split()

        if len(parts) >= 2:
            status = parts[1]

    for line in lines:
        if line.lower().startswith("server:"):
            server_value = line.split(":", 1)[1].strip()

            if "/" in server_value:
                server, version = server_value.split("/", 1)
            else:
                server = server_value

    return {
        "service": service,
        "status": status,
        "server": server,
        "version": version,
        "version_detected": version != "Unknown",
        "version_source": "Server header" if version != "Unknown" else "Not disclosed"
    }
