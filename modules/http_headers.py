import requests
import time


def get_http_headers(url):
    start_time = time.time()

    try:
        response = requests.get(
            url,
            timeout=10
        )

        end_time = time.time()
        response_time = end_time - start_time

        server = response.headers.get(
            "Server",
            "Not Disclosed"
        )

        x_powered_by = response.headers.get(
           "X-Powered-By",
           "Not Disclosed"
        )

        content_type = response.headers.get(
            "Content-Type",
            "Unknown"
        )

        content_length = response.headers.get(
            "Content-Length",
            "Unknown"
        )

        content_security_policy = response.headers.get(
            "Content-Security-Policy"
        )

        strict_transport_security = response.headers.get(
            "Strict-Transport-Security"
        )

        x_content_type_options = response.headers.get(
            "X-Content-Type-Options"
        )

        x_frame_options = response.headers.get(
            "X-Frame-Options"
        )

        referrer_policy = response.headers.get(
            "Referrer-Policy"
        )

        return {
            "server": server,
            "x_powered_by": x_powered_by,
            "content_type": content_type,
            "content_length": content_length,
            "response_time": response_time,
            "content_security_policy": content_security_policy,
            "strict_transport_security": strict_transport_security,
            "x_content_type_options": x_content_type_options,
            "x_frame_options": x_frame_options,
            "referrer_policy": referrer_policy
        }

    except requests.exceptions.Timeout:
        return {
            "server": "Not Disclosed",
            "x_powered_by": "Not Disclosed",
            "content_type": "Unknown",
            "content_length": "Unknown",
            "response_time": None,
            "content_security_policy": None,
            "strict_transport_security": None,
            "x_content_type_options": None,
            "x_frame_options": None,
            "referrer_policy": None,
            "error": "HTTP request timed out"
        }

    except requests.exceptions.RequestException as error:
        return {
            "server": "Not Disclosed",
            "x_powered_by": "Not Disclosed",
            "content_type": "Unknown",
            "content_length": "Unknown",
            "response_time": None,
            "content_security_policy": None,
            "strict_transport_security": None,
            "x_content_type_options": None,
            "x_frame_options": None,
            "referrer_policy": None,
            "error": f"HTTP request failed: {error}"
        }
