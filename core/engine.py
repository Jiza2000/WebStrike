from modules.target import validate_target, resolve_ip


def run_scan(target):
    """
    Main scan engine.
    Calls all scanning modules and returns a single result dictionary.
    """

    target = validate_target(target)

    results = {
        "target": target,
        "ip": resolve_ip(target)
    }

    return results
