import socket


def scan_ports(ip):
    port_results = {}

    ports = [22, 80, 443]

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)

        try:
            sock.connect((ip, port))
            port_results[port] = "Open"

        except:
            port_results[port] = "Closed"

        finally:
            sock.close()

    return port_results
