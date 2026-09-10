"""v0.4.0 round-5 – insecure randomness for tokens/OTP vs benign random use."""
import random
import string


def generate_token():
    # VULNERABLE: random used to mint a security token.
    token = "".join(random.choices(string.ascii_letters + string.digits, k=32))
    return token


def generate_otp():
    # VULNERABLE: predictable OTP.
    return random.randint(100000, 999999)


def make_session_id():
    # VULNERABLE: session id from random.
    return "".join(random.choice("0123456789abcdef") for _ in range(32))


def shuffle_gift_cards(cards):
    # SAFE: benign random shuffling, not security material.
    random.shuffle(cards)
    return cards


def pick_winner(entries):
    # SAFE: random pick for a lottery, not a token/key.
    return random.choice(entries)
