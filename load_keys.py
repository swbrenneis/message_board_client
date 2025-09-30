import requests

passphrase = input("Enter passphrase: ")

response = requests.get(f"http://localhost:8446/enclave/loadKeys/{passphrase}")

print(response.text)