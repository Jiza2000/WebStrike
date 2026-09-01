import dns.resolver


def get_records(domain, record_type):
    records = []

    try:
        answers = dns.resolver.resolve(domain, record_type)

        for answer in answers:
            records.append(str(answer))

    except dns.resolver.NoAnswer:
        # Record type does not exist for this domain
        pass

    except dns.resolver.NXDOMAIN:
        # Domain does not exist
        pass

    except dns.resolver.NoNameservers:
        # No DNS server could provide an answer
        pass

    except dns.resolver.Timeout:
        # DNS query timed out
        pass

    except Exception:
        # Prevent DNS errors from stopping the entire scan
        pass

    return records


def get_dns_records(domain):
    a_records = get_records(domain, "A")
    mx_records = get_records(domain, "MX")
    ns_records = get_records(domain, "NS")
    txt_records = get_records(domain, "TXT")

    return {
        "A": a_records,
        "MX": mx_records,
        "NS": ns_records,
        "TXT": txt_records
    }
