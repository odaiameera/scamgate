from scamgate.redact import redact_text, redact_url


def test_redact_url_drops_password_query_values_and_fragment():
    r = redact_url("https://bob:hunter2@shop.example/pay?token=abc123&x=1#frag")
    assert "hunter2" not in r and "abc123" not in r and "frag" not in r
    assert r.startswith("https://") and "shop.example/pay" in r and "token=" in r


def test_redact_url_masks_long_path_tokens():
    r = redact_url("https://x.example/reset/9f8e7d6c5b4a39281706f5e4d3c2b1a0ffeeddcc")
    assert "9f8e7d6c5b4a" not in r and "<token>" in r


def test_redact_text_masks_cards_ibans_emails_and_secrets():
    t = ("card 4111 1111 1111 1111, iban IE29AIBK93115212345678, mail bob@example.com, "
         "password=hunter2 key sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
    r = redact_text(t)
    for secret in ["4111 1111 1111 1111", "93115212345678", "bob@", "hunter2", "ABCDEFGHIJKLMNOP"]:
        assert secret not in r, secret
    assert "<card>" in r and "IE29" in r and "example.com" in r


def test_non_luhn_numbers_kept():
    assert "1234567890123" in redact_text("order 1234567890123")


def test_truncates():
    assert len(redact_text("a" * 1000, limit=50)) <= 51
