import requests
import hashlib
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes

private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()
pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

initiate_registration = {'screenName' : 'StevieWB', 'publicKey' : pem.decode('UTF-8')}
response = requests.post('http://localhost:8446/enclave/register', json=initiate_registration)
registered = response.json()

print(f"Public ID: {registered['publicId']}")

signing_public_key = serialization.load_pem_public_key(
    registered['signingPublicKey'].encode('UTF-8'),
    backend=default_backend()
)

digest = hashlib.sha256()
digest.update(registered['publicId'].encode('UTF-8'))
digest.update(registered['enclaveKey'].encode('UTF-8'))
digest.update(registered['signingPublicKey'].encode('UTF-8'))
digest.update(registered['status'].encode('UTF-8'))
hash_bytes = digest.digest()

signature_bytes = base64.b64decode(registered['signature'])

# Verify the signature
try:
    signing_public_key.verify(signature_bytes, hash_bytes, ec.ECDSA(hashes.SHA256()))
    print("Signature is valid.")
except Exception as e:
    print("Signature verification failed:", e)
