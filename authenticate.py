import base64
import hashlib
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding

import crypto_util

screen_name = input("Enter screen name: ")
# Get the passwords for the private keys
encryption_password = input("Enter encryption key password: ")
signing_password = input("Enter signing key password: ")

data_file = f'{screen_name}_data'

# Load the user signing private key
with open("signing_private_key.pem", "rb") as key_file:
    signing_private_key = serialization.load_pem_private_key(
        key_file.read(),
    password=signing_password.encode('utf-8'),
    backend=default_backend()
)

# Load the encryption private key (used to decrypt enclave key)
with open('encryption_private_key.pem', 'rb') as key_file:
    encryption_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=encryption_password.encode('utf-8'),
        backend=default_backend()
    )

# Load the user details
lines = []
with open(data_file, 'r') as file:
    for line in file.readlines():
        lines.append(line)

screen_name = lines[0].strip()
public_id = lines[1].strip()
enclave_key = lines[2].strip()

# Load the server signing public key
with open('server_signing', 'rb') as file:
    server_signing_public_key = serialization.load_pem_public_key(
        file.read(),
        backend=default_backend()
)

# Decode and decrypt the enclave key. It is double encrypted. The version
# in the file is encrypted to the user encryption key
enclave_key_bytes = base64.b64decode(enclave_key)
cleartext = crypto_util.decrypt_bytes(enclave_key_bytes, encryption_private_key)
enclave_key_string = cleartext.decode('utf-8')

digest = hashlib.sha256()
digest.update(public_id.encode('utf-8'))
digest.update(enclave_key_string.encode('utf-8'))
message = digest.digest()
message_string = message.hex()

# Generate the signature
signature = signing_private_key.sign(message, ec.ECDSA(hashes.SHA256()))
signature_hex = signature.hex()
signature_encoded = base64.b64encode(signature).decode('UTF-8')

initiate_authentication = { 'publicId': public_id, 'enclaveKey': enclave_key_string, 'signature': signature_encoded}

response = requests.post('http://localhost:8446/enclave/authenticate', json=initiate_authentication)
authenticated = response.json()

if not authenticated['authenticated']:
    print(f"Authentication failed")
    quit()

# Verify the signature
signature_bytes = base64.b64decode(authenticated['signature'])
sha256 = hashlib.sha256()
sha256.update(authenticated['sessionId'].encode('utf-8'))
sha256.update(authenticated['sessionKey'].encode('utf-8'))
signed_bytes = sha256.digest()

try:
    server_signing_public_key.verify(signature_bytes, signed_bytes, ec.ECDSA(hashes.SHA256()))
    print("Signature is valid.")
except Exception as e:
    print("Signature verification failed:", e)
    quit()

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

session_key = base64.b64encode(decrypted_data).decode('UTF-8')

with open("session_data", 'w') as file:
    file.write(session_key)
    file.write('\n')
    file.write(authenticated['sessionId'])
    file.write('\n')

print("Authenticated")