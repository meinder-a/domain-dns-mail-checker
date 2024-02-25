import sys
import dns.resolver
import json

def check_mx(domain):
    try:
        answer = dns.resolver.resolve(domain, "MX")
        return [str(rdata) for rdata in answer], 1
    except Exception as e:
        return str(e), 0

def check_a_aaaa(domain):
    results = {}
    scores = 0
    for record_type in ["A", "AAAA"]:
        try:
            answer = dns.resolver.resolve(domain, record_type)
            results[record_type] = [str(rdata) for rdata in answer]
            scores += 1
        except Exception as e:
            results[record_type] = str(e)
    return results, scores

def check_spf(domain):
    try:
        txt_records = dns.resolver.resolve(domain, "TXT")
        for rdata in txt_records:
            txt_record = rdata.to_text()
            if "v=spf1" in txt_record:
                return txt_record, 1
        return "No SPF record found", 0
    except Exception as e:
        return str(e), 0

def check_dmarc(domain):
    try:
        dmarc_record = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        return [str(rdata) for rdata in dmarc_record], 2
    except Exception as e:
        return "No DMARC record found", 0

def check_dkim(domain, selectors):
    for selector in selectors:
        try:
            dkim_record = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            return [str(rdata) for rdata in dkim_record], 1
        except Exception as e:
            continue
    return "No DKIM record found with common selectors", 0

def check_dns(domain):
    results = {}
    scores = 0

    # Check for various DNS records
    results["MX"], mx_score = check_mx(domain)
    a_aaaa_results, a_aaaa_score = check_a_aaaa(domain)
    results.update(a_aaaa_results)
    results["SPF"], spf_score = check_spf(domain)
    results["DMARC"], dmarc_score = check_dmarc(domain)

    # Common DKIM selectors to guess
    dkim_selectors = ['default', 'google', 'mail', 'k1', 'smtp']
    results["DKIM"], dkim_score = check_dkim(domain, dkim_selectors)

    # Calculate total scores
    scores = mx_score + a_aaaa_score + spf_score + dmarc_score + dkim_score

    return results, scores

def main():
    if len(sys.argv) != 2:
        print("This script requires a domain name as the first argument.")
        sys.exit(-1)

    domain = sys.argv[1]
    results, total_score = check_dns(domain)

    # Prepare JSON output
    output = {
        "domain": domain,
        "results": results,
        "total_score": total_score
    }

    print(json.dumps(output, indent=4))

if __name__ == "__main__":
    main()
