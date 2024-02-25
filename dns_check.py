"""
This module checks various DNS configurations for mailing security of a domain.
It includes checks for MX, A, AAAA, SPF, DMARC, and DKIM records.
"""

from dataclasses import dataclass, asdict
from typing import List, Callable, Optional
import json
import re
import sys
import smtplib
import socket
import dns.resolver
import dns.exception


@dataclass
class RecordResult:
    """Class to store individual DNS record check results."""
    record_data: Optional[List[str]]
    detail: str
    score: int

    def to_dict(self):
        """ Needed for serialization """
        return asdict(self)


@dataclass
class ServiceCheckResult:
    """Class to store service check results."""
    smtp: RecordResult

    def to_dict(self):
        """ Needed for serialization """
        return asdict(self)


@dataclass
class RecordsResult:
    """Class to store all DNS records check results."""
    mx: RecordResult
    a: RecordResult
    aaaa: RecordResult
    spf: RecordResult
    dmarc: RecordResult
    dkim: RecordResult
    bimi: RecordResult

    def to_dict(self):
        """ Needed for serialization """
        return {key: getattr(self, key).to_dict() for key in self.__dict__}


@dataclass
class DNSCheckResult:
    """Class to store overall results."""
    records: RecordsResult
    services: ServiceCheckResult
    total_score: int

    def to_dict(self):
        """ Needed for serialization """
        return {
            "records": self.records.to_dict(),
            "services": self.services.to_dict(),
            "total_score": self.total_score}


common_dkim_selectors = ['default', 'google', 'mail', 'k1', 'smtp']


def dns_query(domain: str, record_type: str, process_func: Callable[[
              dns.resolver.Answer], RecordResult]) -> RecordResult:
    """Perform DNS query and process the results."""
    try:
        answer = dns.resolver.resolve(domain, record_type)
        return process_func(answer)
    except dns.exception.DNSException:
        return RecordResult(None, f"No {record_type} record found", 0)


def process_mx(answer: dns.resolver.Answer) -> RecordResult:
    """Process MX record query results."""
    return RecordResult([str(rdata) for rdata in answer], "Found MX record", 1)


def check_smtp_server(answer: dns.resolver.Answer) -> RecordResult:
    """Check if SMTP server is running and verify its configuration."""
    servers = [str(rdata) for rdata in answer]
    for server in servers:
        mx_server_ip = server.split(' ')[-1]
        ports = [25, 465, 587]
        for port in ports:
            try:
                with smtplib.SMTP(mx_server_ip, port, timeout=3) as server:
                    code, _ = server.noop()
                    if code == 250:  # 250 is a successful response from SMTP server
                        return RecordResult(
                            [f"SMTP server running on {mx_server_ip} {port}"],
                            "SMTP server found",
                            1)
            except (socket.gaierror, socket.timeout, smtplib.SMTPException, ConnectionRefusedError):
                continue

    return RecordResult(
        None, "Unable to confirm SMTP server on common ports. This does not necessarily \
                        indicate the absence of an SMTP server; it may be due to security measures, \
                        non-standard configurations, or other network policies.", 0)


def process_a_aaaa(
        answer: dns.resolver.Answer,
        record_type: str) -> RecordResult:
    """Process A or AAAA record query results."""
    return RecordResult([str(rdata) for rdata in answer],
                        f"Found {record_type} record", 1)


def process_spf(answer: dns.resolver.Answer) -> RecordResult:
    """Process SPF record query results."""
    records = [str(rdata) for rdata in answer if "v=spf1" in str(rdata)]
    return RecordResult(
        records,
        "Found SPF record",
        1 if records else 0)


def process_dmarc(domain: str) -> RecordResult:
    """Process DMARC record query results."""
    try:
        dmarc_answer = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_records = [str(rdata)
                         for rdata in dmarc_answer if "v=DMARC1" in str(rdata)]
        return RecordResult(
            dmarc_records,
            "Found DMARC record",
            2 if dmarc_records else 0)
    except dns.exception.DNSException:
        return RecordResult(None, "No DMARC record found", 0)


def process_dkim(domain: str) -> RecordResult:
    """Attempt to find DKIM records using common selectors."""
    for selector in common_dkim_selectors:
        try:
            dkim_answer = dns.resolver.resolve(
                f"{selector}._domainkey.{domain}", "TXT")
            dkim_records = [str(rdata)
                            for rdata in dkim_answer if "v=DKIM1" in str(rdata)]
            if dkim_records:
                message: str = f"Found DKIM record with selector '{selector}'"
                return RecordResult(dkim_records, message, 1)
        except dns.exception.DNSException:
            continue
    return RecordResult(None, "No DKIM record found with common selectors", 0)


def process_bimi(domain: str) -> RecordResult:
    """Check and process BIMI record for the given domain."""
    bimi_record_domain = f"default._bimi.{domain}"
    try:
        answer = dns.resolver.resolve(bimi_record_domain, "TXT")
        bimi_record = [str(rdata)
                       for rdata in answer if "v=BIMI1" in str(rdata)]
        if bimi_record:
            # Extract SVG URL from the BIMI record
            svg_url = extract_svg_url(bimi_record[0])
            return RecordResult(
                bimi_record,
                f"BIMI record found: \
                <img \
                    style=\"display:in-line-block;\" \
                    width=\"24\" height=\"24\" src=\"{svg_url}\" \
                >",
                1)
        return RecordResult(None, "No BIMI record found", 0)
    except dns.exception.DNSException:
        return RecordResult(None, "Failed to fetch BIMI record", 0)


def extract_svg_url(bimi_record: str) -> str:
    """Extract the SVG URL from a BIMI record."""
    match = re.search(r'l=([^";]+)', bimi_record)
    return match.group(1) if match else "No SVG URL found"


def check_dns(domain: str) -> DNSCheckResult:
    """Check various DNS records for the given domain."""
    dns_check_functions = {
        'mx': lambda: dns_query(
            domain,
            "MX",
            process_mx),
        'a': lambda: dns_query(
            domain,
            "A",
            lambda a: process_a_aaaa(
                a,
                "A")),
        'aaaa': lambda: dns_query(
            domain,
            "AAAA",
            lambda a: process_a_aaaa(
                a,
                "AAAA")),
        'spf': lambda: dns_query(
            domain,
            "TXT",
            process_spf),
        'dmarc': lambda: process_dmarc(domain),
        'dkim': lambda: process_dkim(domain),
        'bimi': lambda: process_bimi(domain)}

    records_result = {key: func() for key, func in dns_check_functions.items()}
    total_score = sum(result.score for result in records_result.values())

    smtp_check_result: RecordResult = dns_query(
        domain,
        "MX",
        check_smtp_server)

    return DNSCheckResult(
        records=RecordsResult(**records_result),
        services=ServiceCheckResult(smtp=smtp_check_result),
        total_score=total_score + smtp_check_result.score)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 dns_check.py example.com")
        sys.exit(-1)

    result = check_dns(sys.argv[1])
    jsonData: str = json.dumps(result.to_dict(), indent=4)
    print(jsonData)
