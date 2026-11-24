from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def wrap_data_key(public_key: rsa.RSAPublicKey, data_key: bytes) -> bytes:
    algorithm = hashes.SHA256()
    oaep = padding.OAEP(mgf=padding.MGF1(algorithm), algorithm=algorithm, label=None)
    return public_key.encrypt(data_key, oaep)
