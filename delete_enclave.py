import requests

import crypto_util

data_file = input("Enter data file name: ")
# Load the user details
lines = []
with open(data_file, 'r') as file:
    for line in file.readlines():
        lines.append(line)

screen_name = lines[0].strip()
public_id = lines[1].strip()
enclave_key = lines[2].strip()

to_hash = [
    screen_name,
    public_id,
    enclave_key,
]

signing_password = input('Enter signing password: ')
signing_private_key = crypto_util.private_key_from_file('signing_private_key.pem', signing_password)
signature = crypto_util.sign_message(to_hash, signing_private_key)

initiate_deletion = {'screenName': screen_name, 'publicId': public_id, 'enclaveKey': enclave_key, 'signature': signature}
response = requests.post('http://localhost:8446/enclave/delete', json=initiate_deletion)
deleted = response.json()

if deleted['deleted']:
    print("Enclave deleted")
else:
    print("Enclave not deleted")
