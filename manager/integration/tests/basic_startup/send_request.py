


import requests
import requests_unixsocket

# patch requests library so that it supports unix socket
requests_unixsocket.monkeypatch()

PAYLOAD_PATH = "./payload.json"
with open(PAYLOAD_PATH, "r") as file:
	PAYLOAD = file.read()

# send the config
r = requests.post('http+unix://%2Ftmp%2Fmanager.sock/config', data=PAYLOAD)
r.raise_for_status()
