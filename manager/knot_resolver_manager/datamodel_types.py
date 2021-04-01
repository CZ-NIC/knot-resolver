import re

IPV4ADDR = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

IPV6_PREFIX_96 = re.compile(r"^([0-9A-Fa-f]{1,4}:){2}:($|/96)$")
