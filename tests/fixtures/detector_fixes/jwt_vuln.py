"""Insecure JWT fixtures — must be detected."""
import jwt


def make_none_token(user_id):
    token = jwt.encode({"user": user_id}, "secret", algorithm="none")
    return token


def decode_no_verify(token):
    data = jwt.decode(token, options={"verify_signature": False})
    return data


def decode_verify_false(token):
    data = jwt.decode(token, "secret", verify=False, algorithms=["none"])
    return data
