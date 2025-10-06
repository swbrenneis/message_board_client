import base64
import crypto_util
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

screen_name = input("Enter screen name: ")

# Load the private key
password = input("Enter encryption key password: ")
encryption_private_key = crypto_util.private_key_from_file("encryption_private_key.pem", password)
encryption_public_key = encryption_private_key.public_key()

with open("encryption_public_key.pem", "r") as key_file:
    encryption_pem_data = key_file.read()

with open("signing_public_key.pem", "r") as key_file:
    signing_pem_data = key_file.read()

initiate_registration = {'screenName' : screen_name, 'encryptionPublicKey' : encryption_pem_data, 'signingPublicKey': signing_pem_data}
response = requests.post('http://localhost:8446/enclave/register', json=initiate_registration)
registered = response.json()

if not registered['success']:
    print(f"Registration failed: {registered['status']}")
    quit()

with open(f'{screen_name}_data', 'w') as file:
    file.write(screen_name)
    file.write('\n')
    file.write(registered['publicId'])
    file.write('\n')
    file.write(registered['enclaveKey'])
    file.write('\n')

print(f"Public ID: {registered['publicId']}")

server_signing_public_key = crypto_util.public_key_from_string(registered['signingPublicKey'])

print(f"Enclave key: {registered['enclaveKey']}")
print(f"Signing public key: {registered['signingPublicKey']}")

strings_to_hash = [
registered['publicId'],
registered['enclaveKey'],
registered['signingPublicKey'],
registered['status']
]
hash_bytes = crypto_util.hash_strings(strings_to_hash)

signature_bytes = base64.b64decode(registered['signature'])

# Verify the signature
try:
    server_signing_public_key.verify(signature_bytes, hash_bytes, ec.ECDSA(hashes.SHA256()))
    print("Signature is valid.")
except Exception as e:
    print("Signature verification failed:", e)
