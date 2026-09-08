from typing import Any, Dict, List


def validate_ip(ip: str, firewall_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [log for log in firewall_logs if log.get("src_ip") == ip or log.get("dst_ip") == ip]


def validate_domain(domain: str, dns_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [log for log in dns_logs if log.get("domain") == domain]


def validate_hash(file_hash: str, endpoint_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [log for log in endpoint_logs if log.get("file_hash") == file_hash]
