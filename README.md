# Domain DNS mail checker

## Install
As easy as it looks, just run the following:
```sh
➜ make install
```

## Run
Slightly toughier:
```sh
➜ make run domain=gmail.com
```
Result:
```json
{
    "domain": "gmail.com",
    "results": {
        "MX": [
            "5 gmail-smtp-in.l.google.com.",
            "10 alt1.gmail-smtp-in.l.google.com.",
            "20 alt2.gmail-smtp-in.l.google.com.",
            "40 alt4.gmail-smtp-in.l.google.com.",
            "30 alt3.gmail-smtp-in.l.google.com."
        ],
        "A": [
            "142.250.179.69"
        ],
        "AAAA": [
            "2a00:1450:4007:813::2005"
        ],
        "SPF": "\"v=spf1 redirect=_spf.google.com\"",
        "DMARC": [
            "\"v=DMARC1; p=none; sp=quarantine; rua=mailto:mailauth-reports@google.com\""
        ],
        "DKIM": "No DKIM record found with common selectors"
    },
    "total_score": 6
}
```
