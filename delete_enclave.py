import base64

import requests

import crypto_util

screen_name = input("Enter screen name: ")
signing_password = input('Enter signing password: ')

# Load the user details
lines = []
with open(f'{screen_name}_data', 'r') as file:
    for line in file.readlines():
        lines.append(line)

public_id = lines[1].strip()

# Load the session details
session_lines = []
with open('session_data', 'r') as file:
    for line in file.readlines():
        session_lines.append(line)

session_key = session_lines[0].strip()
session_id = session_lines[1].strip()

# Encrypt the screen name using the session key
decoded_session_key = base64.b64decode(session_key)
ciphertext = crypto_util.aes_encrypt_bytes(screen_name.encode('utf-8'), decoded_session_key)
encoded_screen_name = base64.b64encode(ciphertext).decode('UTF-8')

#Encrypt the public ID
ciphertext = crypto_util.aes_encrypt_bytes(public_id.encode('utf-8'), decoded_session_key)
encoded_public_id = base64.b64encode(ciphertext).decode('UTF-8')

to_hash = [
    session_id,
    encoded_screen_name,
    encoded_public_id,
]
signing_private_key = crypto_util.private_key_from_file('signing_private_key.pem', signing_password)
signature = crypto_util.sign_message(to_hash, signing_private_key)  # Returns base 64 encoded bytes
signature_string = signature.decode('utf-8')

initiate_deletion = {'sessionId': session_id, 'screenName': encoded_screen_name, 'publicId': encoded_public_id, 'signature': signature_string}
response = requests.post('http://localhost:8446/enclave/delete', json=initiate_deletion)
if (response.status_code != 200):
    print(f'{response.status_code}: {response.text}')
    quit()

deleted = response.json()

if deleted['deleted']:
    print("Enclave deleted")
else:
    print("Enclave not deleted")
