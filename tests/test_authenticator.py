import pytest
from jwt_authenticator import JWTAuthenticator

def test_decode_token():
    secret_key = "test_secret"
    db_config = {}
    auth = JWTAuthenticator(db_config, secret_key)

    token = jwt.encode({"test": "payload"}, secret_key, algorithm="HS256")
    decoded = auth._decode_token(token)
    assert decoded["test"] == "payload"
