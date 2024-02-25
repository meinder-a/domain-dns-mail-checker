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
    "MX": {
        "record_data": [
            "30 alt3.gmail-smtp-in.l.google.com.",
            "20 alt2.gmail-smtp-in.l.google.com.",
            "40 alt4.gmail-smtp-in.l.google.com.",
            "5 gmail-smtp-in.l.google.com.",
            "10 alt1.gmail-smtp-in.l.google.com."
        ],
        "detail": "Found MX record",
        "score": 1
    },
    "A": {
        "record_data": [
            "142.250.179.101"
        ],
        "detail": "Found A record",
        "score": 1
    },
    "AAAA": {
        "record_data": [
            "2a00:1450:4007:818::2005"
        ],
        "detail": "Found AAAA record",
        "score": 1
    },
    "SPF": {
        "record_data": [
            "\"v=spf1 redirect=_spf.google.com\""
        ],
        "detail": "Found SPF record",
        "score": 1
    },
    "DMARC": {
        "record_data": [
            "\"v=DMARC1; p=none; sp=quarantine; rua=mailto:mailauth-reports@google.com\""
        ],
        "detail": "Found DMARC record",
        "score": 2
    },
    "DKIM": {
        "record_data": null,
        "detail": "No DKIM record found with common selectors",
        "score": 0
    },
    "total_score": 6
}
```
