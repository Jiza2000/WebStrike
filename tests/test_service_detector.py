from modules.service_detector import parse_http_banner


def test_parse_http_banner():
    banner = (
        "HTTP/1.1 200 OK\r\n"
        "Server: nginx/1.24.0\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
    )

    result = parse_http_banner(banner)

    assert result["service"] == "HTTP"
    assert result["status"] == "200"
    assert result["server"] == "nginx"

