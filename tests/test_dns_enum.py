from modules.dns_enum import get_dns_records


def test_dns_noanswer_handling(monkeypatch):

    class FakeResolver:
        def resolve(self, hostname, record_type):
            raise Exception("NoAnswer")

    monkeypatch.setattr(
        "modules.dns_enum.dns.resolver.Resolver",
        lambda: FakeResolver()
    )

    result = get_dns_records("www.example.com")

    assert result is not None
