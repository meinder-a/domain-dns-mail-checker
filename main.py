import sys
import json
from typing import List, Callable, Optional
import dns.resolver
import dns.exception
from dataclasses import dataclass

@dataclass
class RecordResult:
    record_data: Optional[List[str]]
    detail: str
    score: int

@dataclass
class DNSCheckResult:
    MX: RecordResult
    A: RecordResult
    AAAA: RecordResult
    SPF: RecordResult
    DMARC: RecordResult
    DKIM: RecordResult
    total_score: int

def dns_query(domain: str, record_type: str, process_func: Callable[[dns.resolver.Answer], RecordResult]) -> RecordResult:
    """Perform DNS query and process the results."""
    try:
        answer = dns.resolver.resolve(domain, record_type)
        return process_func(answer)
    except dns.exception.DNSException:
        return RecordResult(None, f"No {record_type} record found", 0)

def process_mx(answer: dns.resolver.Answer) -> RecordResult:
    """Process MX record query results."""
    return RecordResult([str(rdata) for rdata in answer], "Found MX record", 1)

def process_a_aaaa(answer: dns.resolver.Answer, record_type: str) -> RecordResult:
    """Process A or AAAA record query results."""
    return RecordResult([str(rdata) for rdata in answer], f"Found {record_type} record", 1)

def process_spf(answer: dns.resolver.Answer) -> RecordResult:
    """Process SPF record query results."""
    spf_records = [str(rdata) for rdata in answer if "v=spf1" in str(rdata)]
    return RecordResult(spf_records, "Found SPF record", 1 if spf_records else 0)

def process_dmarc(domain: str) -> RecordResult:
    """Process DMARC record query results."""
    try:
        dmarc_answer = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_records = [str(rdata) for rdata in dmarc_answer if "v=DMARC1" in str(rdata)]
        return RecordResult(dmarc_records, "Found DMARC record", 2 if dmarc_records else 0)
    except dns.exception.DNSException:
        return RecordResult(None, "No DMARC record found", 0)

def process_dkim(domain: str) -> RecordResult:
    """Attempt to find DKIM records using common selectors."""
    COMMON_DKIM_SELECTORS = ['default', 'google', 'mail', 'k1', 'smtp']
    for selector in COMMON_DKIM_SELECTORS:
        try:
            dkim_answer = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            dkim_records = [str(rdata) for rdata in dkim_answer if "v=DKIM1" in str(rdata)]
            if dkim_records:
                return RecordResult(dkim_records, f"Found DKIM record with selector '{selector}'", 1)
        except dns.exception.DNSException:
            continue
    return RecordResult(None, "No DKIM record found with common selectors", 0)

def check_dns(domain: str) -> DNSCheckResult:
    """Check various DNS records for the given domain."""
    mx_result = dns_query(domain, "MX", process_mx)
    a_result = dns_query(domain, "A", lambda a: process_a_aaaa(a, "A"))
    aaaa_result = dns_query(domain, "AAAA", lambda a: process_a_aaaa(a, "AAAA"))
    spf_result = dns_query(domain, "TXT", process_spf)
    dmarc_result = process_dmarc(domain)
    dkim_result = process_dkim(domain)

    total_score = sum([mx_result.score, a_result.score, aaaa_result.score, spf_result.score, dmarc_result.score, dkim_result.score])

    return DNSCheckResult(mx_result, a_result, aaaa_result, spf_result, dmarc_result, dkim_result, total_score)

def main():
    """Main function to check DNS configurations for a given domain."""
    if len(sys.argv) != 2:
        print("This script requires a domain name as the first argument.")
        sys.exit(-1)

    domain = sys.argv[1]
    result = check_dns(domain)
    print(json.dumps(result, default=lambda o: o.__dict__, indent=4))

if __name__ == "__main__":
    main()
