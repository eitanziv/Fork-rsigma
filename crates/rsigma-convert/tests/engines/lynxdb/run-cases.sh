#!/bin/sh
# Starts a LynxDB server, ingests every case under /work/cases/<n>/events.ndjson
# into index c<n>, then runs each /work/cases/<n>/q<k>.txt query and writes
# q<k>.out (NDJSON rows), q<k>.err, and q<k>.rc next to it.
set -eu

lynxdb server >/tmp/server.log 2>&1 &
i=0
until lynxdb health >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 100 ]; then
    echo "LynxDB server did not become healthy" >&2
    cat /tmp/server.log >&2
    exit 1
  fi
  sleep 0.1
done

expected=0
for dir in /work/cases/*/; do
  n=$(basename "$dir")
  lynxdb ingest "${dir}events.ndjson" --index "c${n}" >/dev/null
  expected=$((expected + $(grep -c . "${dir}events.ndjson")))
done

# Buffered and flushed events take different query paths with different
# results, so query only once every event is in a segment, as in production.
i=0
until lynxdb status -F json | grep -q '"buffered_events": 0,' &&
  lynxdb status -F json | grep -q "\"total_events\": ${expected},"; do
  i=$((i + 1))
  if [ "$i" -gt 300 ]; then
    echo "LynxDB did not flush ${expected} events" >&2
    lynxdb status -F json >&2
    exit 1
  fi
  sleep 0.1
done

for q in /work/cases/*/q*.txt; do
  base=${q%.txt}
  set +e
  lynxdb query -F ndjson --no-stats --no-color "$(cat "$q")" >"${base}.out" 2>"${base}.err"
  echo $? >"${base}.rc"
  set -e
done
