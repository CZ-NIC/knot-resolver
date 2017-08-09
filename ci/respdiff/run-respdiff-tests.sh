wget https://gitlab.labs.nic.cz/knot/knot-resolver/snippets/69/raw?inline=false -O /tmp/queries.txt
mkdir results;
rm -rf /tmp/respdiff;
python3 /var/opt/respdiff/qprep.py /tmp/respdiff < /tmp/queries.txt && \
python3 /var/opt/respdiff/orchestrator.py /tmp/respdiff -c $(pwd)/ci/respdiff/respdiff.conf && \
python3 /var/opt/respdiff/msgdiff.py /tmp/respdiff -c $(pwd)/ci/respdiff/respdiff.conf && \
python3 /var/opt/respdiff/diffsum.py /tmp/respdiff -c $(pwd)/ci/respdiff/respdiff.conf > results/respdiff.txt
