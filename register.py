import requests
import hashlib
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes

# Load the encrypted PEM file
with open("encryption_private_key.pem", "rb") as key_file:
    encrypted_pem_data = key_file.read()

# Load the private key
password = input("Enter encryption key password: ")
encryption_private_key = serialization.load_pem_private_key(
    encrypted_pem_data,
    password=password.encode('utf-8'),
    backend=default_backend()
)
encryption_public_key = encryption_private_key.public_key()

with open("encryption_public_key.pem", "rb") as key_file:
    pem_data = key_file.read()
pem = pem_data.decode("UTF-8")

initiate_registration = {'screenName' : 'StevieB', 'encryptionPublicKey' : pem}
response = requests.post('http://localhost:8446/enclave/register', json=initiate_registration)
registered = response.json()

if not registered['success']:
    print(f"Registration failed: {registered['status']}")
    quit()

with open('data', 'w') as file:
    file.write('StevieB\n')
    file.write(registered['publicId'])
    file.write('\n')
    file.write(registered['enclaveKey'])
    file.write('\n')

print(f"Public ID: {registered['publicId']}")

signing_public_key = serialization.load_pem_public_key(
    registered['signingPublicKey'].encode('UTF-8'),
    backend=default_backend()
)

print(f"Enclave key: {registered['enclaveKey']}")
print(f"Signing public key: {registered['signingPublicKey']}")

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
