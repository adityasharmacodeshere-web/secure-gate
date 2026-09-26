import hashlib
import logging

from app.main import PrefixRequest, parse_hibp_response


def test_prefix_requires_exact_uppercase_hex():
    assert PrefixRequest(prefix="abcde").prefix == "ABCDE"


def test_prefix_rejects_full_hash():
    full_hash = hashlib.sha1(b"secret").hexdigest()
    try:
        PrefixRequest(prefix=full_hash)
    except Exception:
        pass
    else:
        raise AssertionError("full hash must not be accepted")


def test_padded_response_parser_keeps_only_suffix_and_count():
    suffix = "A" * 35
    result = parse_hibp_response(f"{suffix}:12\nnot-a-secret\n")
    assert result[0].suffix == suffix
    assert result[0].count == 12


def test_logs_do_not_contain_secret(caplog):
    secret = "raw-password-value"
    with caplog.at_level(logging.INFO):
        logging.getLogger("securegate").info("request path=/health")
    assert secret not in caplog.text
