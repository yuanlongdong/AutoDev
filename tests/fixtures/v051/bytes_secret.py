"""v0.5.1 — hardcoded bytes literals that ARE secrets.

Variable names carrying key / secret / password / token / iv / aes semantics
assigned to a ``b'...'`` / ``b"..."`` literal of at least 8 bytes must be
reported.  Mirrors ``crypto-target`` ``AES_KEY`` / ``AES_IV``.
"""

# BAD: 16-byte hardcoded AES key
AES_KEY = b'0123456789abcdef'

# BAD: hardcoded IV
AES_IV = b'fedcba9876543210'

# BAD: bytes token
SESSION_TOKEN = b'abcdef0123456789'

# BAD: bytes password
DB_PASSWORD = b's3cr3tpassw0rd!!'
