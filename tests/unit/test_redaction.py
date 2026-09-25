from threatintel.extraction.redaction import REDACTED, fingerprint, redact


def test_combolist_redacted_accounts_kept() -> None:
    r = redact("a@corp.example:Summer2024!\nb@corp.example|hunter22", key=b"k")
    assert "Summer2024!" not in r.text and "hunter22" not in r.text
    assert r.text.count(REDACTED) == 2
    assert [a.account for a in r.accounts] == ["a@corp.example", "b@corp.example"]
    assert all(a.fingerprint for a in r.accounts)
    assert r.credential_present


AWS_DOC_EXAMPLE_KEY = "AKIA" + "IOSFODNN7EXAMPLE"  # AWS's published documentation example


def test_key_value_and_tokens() -> None:
    text = (
        f"password=Pa55w0rd api_key: abcdef123 {AWS_DOC_EXAMPLE_KEY} ghp_"
        + "a" * 36
        + " eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U "
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123"
    )
    r = redact(text)
    for secret in (
        "Pa55w0rd",
        "abcdef123",
        AWS_DOC_EXAMPLE_KEY,
        "ghp_",
        "eyJhbGci",
        "abcdefghijklmnopqrstuvwxyz0123",
    ):
        assert secret not in r.text, secret
    assert r.redactions >= 6


def test_private_key_block() -> None:
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----"
    assert "MIIBOgIBAAJBAK" not in redact(pem).text


def test_no_false_positives_on_prose() -> None:
    prose = (
        "The stealer steals the session cookie and saved password stores. Contact analyst@corp.example: "
        "see http://u@evil.example:8080/x for the secret of the kit."
    )
    r = redact(prose)
    assert r.text == prose
    assert r.redactions == 0


def test_fingerprint_is_keyed() -> None:
    assert fingerprint("s3cret", b"") is None
    assert fingerprint("s3cret", b"k1") != fingerprint("s3cret", b"k2")
    assert fingerprint("s3cret", b"k1") == fingerprint("s3cret", b"k1")
