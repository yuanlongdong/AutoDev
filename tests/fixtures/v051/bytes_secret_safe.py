"""v0.5.1 — bytes literals that must NOT be reported.

* too short (< 8 bytes);
* variable name carries no key / secret / password / token / iv / aes
  semantics (``plaintext`` is application data, not a key).
"""

# SAFE: 1 byte, below the 8-byte floor
SHORT_KEY = b'x'

# SAFE: 7 bytes, still below the floor
SEVEN_BYTE_KEY = b'1234567'

# SAFE: long bytes but the name does not look like a secret
PLAINTEXT_BUFFER = b'0123456789abcdef0123456789abcdef'

# SAFE: ordinary string secret (already covered by the string-literal rule,
# present here only to confirm the bytes rule does not double-report).
JWT_SECRET = 'secret123'
