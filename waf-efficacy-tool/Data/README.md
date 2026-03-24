# Datasets

Place your datasets here:

- `Malicious/` - Malicious payloads (True Positive testing)
- `Legitimate/` - Legitimate requests (False Positive testing)

## Dataset Format

Each dataset should be a JSON file with the following structure:

```json
[
  {
    "method": "GET",
    "url": "/?p=<payload>",
    "headers": {
      "User-Agent": "Mozilla/5.0...",
      "Connection": "close"
    },
    "data": ""
  }
]
```

## Sources

- **Malicious:** [MGM WAF Payload Collection](https://github.com/mgm-sp/WAF-Payload-Collection)
- **Legitimate:** [OpenAppSec Datasets](https://downloads.openappsec.io/waf-comparison-project/)

## Download

```bash
# Download from WAF Comparison Project
wget https://downloads.openappsec.io/waf-comparison-project/malicious.zip
wget https://downloads.openappsec.io/waf-comparison-project/legitimate.zip

# Extract
unzip malicious.zip -d Data/
unzip legitimate.zip -d Data/
```
