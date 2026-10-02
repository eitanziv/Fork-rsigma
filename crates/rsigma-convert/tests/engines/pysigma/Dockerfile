# pySigma's TextQueryTestBackend, the reference for rsigma's `test` backend.
# Dependencies are pinned with hashes in requirements.txt, generated from
# requirements.in with:
#   uv pip compile --generate-hashes --python-version 3.13 requirements.in -o requirements.txt
FROM python:3.13-slim@sha256:bb2988715db2cf7ace7b53f38f3cffbef7c7046a656bee66245eb0ed386e2e81
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt
COPY convert.py /usr/local/bin/convert.py
ENTRYPOINT ["python", "/usr/local/bin/convert.py"]
