def validate_ip(ip, firewall_logs):

    matches = []

    for log in firewall_logs:

        if log.get("src_ip") == ip:

            matches.append(log)

    return matches


def validate_domain(domain, dns_logs):

    matches = []

    for log in dns_logs:

        if log.get("domain") == domain:

            matches.append(log)

    return matches


def validate_hash(file_hash, endpoint_logs):

    matches = []

    for log in endpoint_logs:

        if log.get("file_hash") == file_hash:

            matches.append(log)

    return matches