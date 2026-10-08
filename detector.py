import re
from urllib.parse import urlparse


def detect_phishing(url):
    score = 0
    reasons = []

    # Add scheme if user doesn't enter one
    test_url = url
    if not re.match(r"^[a-zA-Z]+://", test_url):
        test_url = "http://" + test_url

    try:
        parsed = urlparse(test_url)
        hostname = parsed.hostname

        if not hostname:
            return {
                "score": 100,
                "status": "SUSPICIOUS",
                "reasons": ["Invalid URL format"]
            }

        # 1. HTTPS check
        if parsed.scheme != "https":
            score += 15
            reasons.append("URL does not use HTTPS")

        # 2. IP address check
        ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

        if re.match(ip_pattern, hostname):
            score += 25
            reasons.append("URL uses an IP address instead of a domain name")

        # 3. Suspicious keywords
        suspicious_keywords = [
            "login",
            "verify",
            "verification",
            "account",
            "update",
            "password",
            "bank",
            "secure",
            "confirm",
            "signin",
            "wallet"
        ]

        found_keywords = []

        for keyword in suspicious_keywords:
            if keyword in url.lower():
                found_keywords.append(keyword)

        if found_keywords:
            score += min(len(found_keywords) * 10, 30)
            reasons.append(
                "Suspicious keywords detected: "
                + ", ".join(found_keywords)
            )

        # 4. URL length
        if len(url) > 100:
            score += 10
            reasons.append("URL is unusually long")

        # 5. @ symbol
        if "@" in url:
            score += 15
            reasons.append("URL contains '@' symbol")

        # 6. Too many hyphens
        if hostname.count("-") >= 3:
            score += 10
            reasons.append("Domain contains multiple hyphens")

        # 7. URL shorteners
        shorteners = [
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "is.gd",
            "cutt.ly"
        ]

        if hostname.lower() in shorteners:
            score += 15
            reasons.append("URL uses a URL shortening service")

        # Keep score between 0 and 100
        score = min(score, 100)

        # Classification
        if score >= 50:
            status = "SUSPICIOUS"
        else:
            status = "SAFE"

        if not reasons:
            reasons.append("No major suspicious characteristics detected")

        return {
            "score": score,
            "status": status,
            "reasons": reasons
        }

    except Exception:
        return {
            "score": 100,
            "status": "SUSPICIOUS",
            "reasons": ["Unable to analyze the URL"]
        }