#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
import json
import time
import sys

import requests


BRANCH_API_ENDPOINT = "https://api.github.com/repos/CZ-NIC/knot-resolver/actions/runs?branch={branch}"  # noqa
TIMEOUT = 15*60  # 15 mins max
POLL_DELAY = 60


def exit(msg='', html_url='', code=1):
    print(msg, file=sys.stderr)
    print(html_url)
    sys.exit(code)


end_time = time.time() + TIMEOUT
while time.time() < end_time:
    response = requests.get(
        BRANCH_API_ENDPOINT.format(branch=sys.argv[1]),
        headers={"Accept": "application/vnd.github.v3+json"})
    if response.status_code == 404:
        pass  # not created yet?
    elif response.status_code == 200:
        data = json.loads(response.content.decode('utf-8'))
        state = data['workflow_runs']['state']
        try:
            run = data['workflow_runs'][0]
            conclusion = run['conclusion']
            html_url = run['html_url']
            commit_sha = run['head_sha']
        except KeyError:
            pass

        if commit_sha != sys.argv[2]:
            exit("Fetched invalid GH Action: commit mismatch. Re-run or push again?")

        if conclusion is None:
            pass
        if conclusion == "success":
            exit("SUCCESS!", html_url, code=0)
        elif isinstance(conclusion, str):
            # failure, neutral, cancelled, skipped, timed_out, or action_required
            exit("GitHub Actions Conclusion: {}!".format(conclusion.upper()), html_url)
    else:
        exit("API Response Code: {}".format(response.status_code), code=2)
    time.sleep(POLL_DELAY)

exit("Timed out!")
