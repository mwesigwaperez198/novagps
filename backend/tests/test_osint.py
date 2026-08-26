import pytest

from osint import (
    DOMAIN_PATTERN,
    IP_PATTERN,
    _detect_email_provider,
    dns_bruteforce,
    email_lookup,
    http_headers,
    phone_lookup,
    reverse_dns,
    scan_dirb,
    scan_nikto,
    scan_sqlmap,
    scan_sublist3r,
    scan_theharvester,
    scan_whatweb,
    scan_wpscan,
    whois_lookup,
)


def test_domain_pattern_valid():
    assert DOMAIN_PATTERN.fullmatch("example.com")
    assert DOMAIN_PATTERN.fullmatch("sub.domain.example.co.uk")
    assert not DOMAIN_PATTERN.fullmatch("not a domain")
    assert not DOMAIN_PATTERN.fullmatch("-bad.com")
    assert not DOMAIN_PATTERN.fullmatch("no_tld")


def test_ip_pattern_valid():
    assert IP_PATTERN.fullmatch("192.168.1.1")
    assert IP_PATTERN.fullmatch("0.0.0.0")
    assert IP_PATTERN.fullmatch("255.255.255.255")
    assert not IP_PATTERN.fullmatch("not-an-ip")
    assert not IP_PATTERN.fullmatch("192.168.1")


def test_whois_invalid_domain():
    result = whois_lookup("not a domain")
    assert "error" in result


def test_dns_bruteforce_invalid_domain():
    result = dns_bruteforce("bad domain!")
    assert "error" in result


def test_reverse_dns_invalid_ip():
    result = reverse_dns("not-an-ip")
    assert "error" in result


def test_http_headers_invalid_url():
    result = http_headers("ftp://example.com")
    assert "error" in result


def test_scan_nikto_invalid_target():
    result = scan_nikto("not valid")
    assert "error" in result


def test_scan_sqlmap_invalid_url():
    result = scan_sqlmap("ftp://bad")
    assert "error" in result


def test_scan_whatweb_invalid_url():
    result = scan_whatweb("not-url")
    assert "error" in result


def test_scan_wpscan_invalid_url():
    result = scan_wpscan("bad")
    assert "error" in result


def test_scan_dirb_invalid_url():
    result = scan_dirb("nope")
    assert "error" in result


def test_scan_sublist3r_invalid_domain():
    result = scan_sublist3r("bad domain")
    assert "error" in result


def test_scan_theharvester_invalid_domain():
    result = scan_theharvester("invalid!")
    assert "error" in result


def test_phone_lookup_uganda_mtn():
    result = phone_lookup("0771234567")
    assert result["carrier"] == "MTN Uganda"
    assert result["line_type"] == "Mobile"
    assert result["country"] == "Uganda"
    assert result["valid"] is True


def test_phone_lookup_uganda_airtel():
    result = phone_lookup("0311234567")
    assert result["carrier"] == "Airtel Uganda"
    assert result["country"] == "Uganda"


def test_phone_lookup_with_country_code():
    result = phone_lookup("771234567", country_code="256")
    assert result["international"] == "+256771234567"


def test_phone_lookup_international():
    result = phone_lookup("+14155551234")
    assert result["country"] == "USA/Canada"


def test_detect_email_provider_google():
    assert "Google" in _detect_email_provider("aspmx.l.google.com")


def test_detect_email_provider_microsoft():
    assert "Microsoft" in _detect_email_provider("outlook-com.olc.protection.outlook.com")


def test_detect_email_provider_protonmail():
    assert "ProtonMail" in _detect_email_provider("mail.protonmail.ch")


def test_email_lookup_invalid():
    result = email_lookup("not-an-email")
    assert "error" in result


def test_phone_lookup_short_number():
    result = phone_lookup("123")
    assert result["valid"] is False
