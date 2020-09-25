#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
import json
import time
import sys

import requests


BRANCH_API_ENDPOINT = "https://api.travis-ci.com/repos/CZ-NIC/knot-resolver/branches/{branch}"
JOB_URL = "https://travis-ci.com/CZ-NIC/knot-resolver/jobs/{job_id}"
TIMEOUT = 600  # 10 mins max
POLL_DELAY = 15

job_id = None


def exit(msg='', code=1):
    print(msg, file=sys.stderr)
    if job_id is not None:
        print(JOB_URL.format(job_id=job_id))
    sys.exit(code)


end_time = time.time() + TIMEOUT
while time.time() < end_time:
    response = requests.get(
        BRANCH_API_ENDPOINT.format(branch=sys.argv[1]),
        headers={"Accept": "application/vnd.travis-ci.2.1+json"})
    if response.status_code == 404:
        pass  # not created yet?
    elif response.status_code == 200:
        data = json.loads(response.content.decode('utf-8'))
        state = data['branch']['state']
        try:
            job_id = data['branch']['job_ids'][0]
        except KeyError:
            pass

        if state == "passed":
            exit("Travis CI Result: PASSED!", code=0)
        elif state == "created" or state == "started":
            pass
        else:
            exit("Travis CI Result: {}!".format(state.upper()))
    else:
        exit("API Response Code: {}".format(response.status_code), code=2)
    time.sleep(POLL_DELAY)

exit("Timed out!")
