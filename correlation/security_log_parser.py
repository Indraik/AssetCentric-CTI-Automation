import csv

def load_firewall_logs(file_path):

    logs = []

    with open(file_path, "r") as f:

        reader = csv.DictReader(f)

        for row in reader:
            logs.append(row)

    return logs


def load_dns_logs(file_path):

    logs = []

    with open(file_path, "r") as f:

        reader = csv.DictReader(f)

        for row in reader:
            logs.append(row)

    return logs


def load_endpoint_logs(file_path):

    logs = []

    with open(file_path, "r") as f:

        reader = csv.DictReader(f)

        for row in reader:
            logs.append(row)

    return logs