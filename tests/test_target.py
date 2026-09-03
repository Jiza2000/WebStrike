from modules.target import validate_target


def test_valid_http_target():
    assert validate_target("http://example.com") == "http://example.com"


def test_valid_https_target():
    assert validate_target("https://example.com") == "https://example.com"


def test_target_without_scheme():
    assert validate_target("example.com") == "https://example.com"
