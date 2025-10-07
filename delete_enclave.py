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

session_id = session_lines[1].strip()

to_hash = [
    session_id,
    screen_name,
    public_id,
]
signing_private_key = crypto_util.private_key_from_file('signing_private_key.pem', signing_password)
signing_public_key = signing_private_key.public_key()
public_numbers = signing_public_key.public_numbers()
x,y = public_numbers.x, public_numbers.y
signature = crypto_util.sign_message(to_hash, signing_private_key)
signature_string = signature.decode('utf-8')

initiate_deletion = {'sessionId': session_id, 'screenName': screen_name, 'publicId': public_id, 'signature': signature_string}
response = requests.post('http://localhost:8446/enclave/delete', json=initiate_deletion)
if (response.status_code != 200):
    print(f'{response.status_code}: {response.text}')
    quit()

deleted = response.json()

if deleted['deleted']:
    print("Enclave deleted")
else:
    print("Enclave not deleted")
