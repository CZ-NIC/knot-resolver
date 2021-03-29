


import subprocess
import time

import requests
import requests_unixsocket

# patch requests library so that it supports unix socket
requests_unixsocket.monkeypatch()

PAYLOAD_PATH = "./payload.json"
with open(PAYLOAD_PATH, "r") as file:
	PAYLOAD = file.read()

# f-string is not working with JSON because of {}
PAYLOAD_F = lambda num: PAYLOAD % num

def set_workers(num: int):
	# send the config
	r = requests.post('http+unix://%2Ftmp%2Fmanager.sock/config', data=PAYLOAD_F(num))
	r.raise_for_status()

def count_running() -> int:
	cmd = subprocess.run("ps aux | grep kresd | grep -v grep", shell=True, stdout=subprocess.PIPE)
	return len(str(cmd.stdout, 'utf8').strip().split("\n"))


print("Initial 1 worker config...")
set_workers(1)
time.sleep(1)
count = count_running()
assert count == 1, f"Unexpected number of kresd instances is running - {count}"

print("Increasing worker count to 8")
set_workers(8)
time.sleep(2)
count = count_running()
assert count == 8, f"Unexpected number of kresd instances is running - {count}"

print("Decreasing worker count to 4")
set_workers(4)
time.sleep(2)
count = count_running()
assert count == 4, f"Unexpected number of kresd instances is running - {count}"
