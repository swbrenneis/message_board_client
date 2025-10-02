import base64
import hashlib
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding

# Load the user details
lines = []
with open('data', 'r') as file:
    for line in file.readlines():
        lines.append(line)

screen_name = lines[0].strip()
public_id = lines[1].strip()
enclave_key = lines[2].strip()

with open('server_signing', 'rb') as file:
    server_signing_pem = file.read()

server_signing_public_key = serialization.load_pem_public_key(
    server_signing_pem,
    backend=default_backend()
)

# Load the encrypted PEM file
with open("signing_private_key.pem", "rb") as key_file:
    encrypted_pem_data = key_file.read()

# Load the private key
password = input("Enter signing key password: ")
signing_private_key = serialization.load_pem_private_key(
    encrypted_pem_data,
    password=password.encode('utf-8'),
    backend=default_backend()
)
# Get the public key from the private key
signing_public_key = signing_private_key.public_key()

# Load the user signing public key PEM
with open("signing_public_key.pem", "r") as file:
    signing_public_key_pem = file.read()

digest = hashlib.sha256()
digest.update(public_id.encode('utf-8'))
digest.update(enclave_key.encode('utf-8'))
digest.update(signing_public_key_pem.encode('utf-8'))
message = digest.digest()
message_string = message.hex()

# Generate the signature
signature = signing_private_key.sign(message, ec.ECDSA(hashes.SHA256()))
signature_hex = signature.hex()
signature_encoded = base64.b64encode(signature).decode('UTF-8')

initiate_authentication = { 'publicId': public_id, 'enclaveKey': enclave_key,
                            'signingPublicKey': signing_public_key_pem,
                            'signature': signature_encoded}

response = requests.post('http://localhost:8446/enclave/authenticate', json=initiate_authentication)
authenticated = response.json()

if not authenticated['authenticated']:
    print(f"Authentication failed")
    quit()

password = input("Enter encryption key password: ")

with open('encryption_private_key.pem', 'rb') as key_file:
    encryption_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=password.encode('utf-8'),
        backend=default_backend()
    )

# Decrypt the sessionKey
encoded_session_key = authenticated['sessionKey']
encrypted_session_key = base64.b64decode(encoded_session_key)

try:
    decrypted_data = encryption_private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
except Exception as e:
    print(f"Decryption failed: {e}")
    quit()


signature_bytes = base64.b64decode(authenticated['signature'])
sha256 = hashlib.sha256()
sha256.update(authenticated['sessionId'].encode('utf-8'))
sha256.update(authenticated['sessionKey'].encode('utf-8'))
signed_bytes = sha256.digest()

# Verify the signature
try:
    server_signing_public_key.verify(signature_bytes, signed_bytes, ec.ECDSA(hashes.SHA256()))
    print("Signature is valid.")
except Exception as e:
    print("Signature verification failed:", e)
    quit()

print("Authenticated")