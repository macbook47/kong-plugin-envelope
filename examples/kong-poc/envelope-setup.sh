#!/usr/bin/env bash
# Phase 3: configures Kong for envelope encryption (spec section 9).
# Safe to re-run: every object is upserted with a fixed name or id.
set -euo pipefail
ADMIN="${KONG_ADMIN:-http://localhost:8080/api}"
AUTH="${KONG_AUTH:-admin:ChangeMe123}"

call() { # method path json
  local code
  code=$(curl -s -o /tmp/kong_resp.json -w '%{http_code}' -u "$AUTH" -X "$1" "$ADMIN$2" \
    -H 'Content-Type: application/json' -d "$3")
  case "$code" in
    200|201) echo "  ok     $1 $2" ;;
    409)     echo "  exists $1 $2" ;;
    *)       echo "  FAIL   $1 $2 -> HTTP $code"; cat /tmp/kong_resp.json; echo; exit 1 ;;
  esac
}

echo "Checking that Kong loaded the envelope plugin"
if ! curl -s -u "$AUTH" "$ADMIN/plugins/enabled" | grep -q '"envelope"'; then
  echo "  The envelope plugin is not enabled. Check KONG_PLUGINS and the volume mount, then restart Kong."
  exit 1
fi
echo "  ok"

echo "Consumers (one per app or team) and their API keys"
for c in poc-ui:poc-ui-key bench-client:bench-key team-y:team-y-key; do
  name=${c%%:*}; key=${c##*:}
  call PUT  "/consumers/$name" "{\"username\":\"$name\",\"tags\":[\"envelope-poc\"]}"
  call POST "/consumers/$name/key-auth" "{\"key\":\"$key\"}"
done

echo "Routes: handshake (answered by Kong itself) and encrypted copies of API A and API B"
call PUT /routes/envelope-handshake '{"paths":["/envelope/handshake"],"methods":["POST","OPTIONS"],"strip_path":true}'
call PUT /services/api-a/routes/secure-api-a '{"paths":["/secure/api-a"],"strip_path":true}'
call PUT /services/api-b/routes/secure-api-b '{"paths":["/secure/api-b"],"strip_path":true}'

CORS='{"name":"cors","config":{"origins":["http://localhost:5173","http://127.0.0.1:5173"],"methods":["GET","POST","PUT","PATCH","DELETE","OPTIONS"],"headers":["Accept","Content-Type","apikey","X-Envelope-Session","X-Envelope-Seq","X-Envelope-Ts"],"exposed_headers":["X-Kong-Proxy-Latency","X-Kong-Upstream-Latency","Via","X-Envelope","X-Envelope-Content-Type"],"max_age":3600}}'
KEYAUTH='{"name":"key-auth","config":{"key_names":["apikey"],"hide_credentials":true}}'

echo "Plugins per route: cors -> key-auth -> envelope (fixed ids so re-runs update in place)"
n=0
for route in envelope-handshake secure-api-a secure-api-b; do
  n=$((n+1))
  if [ "$route" = "envelope-handshake" ]; then ENV='{"name":"envelope","config":{"mode":"handshake"}}'
  else ENV='{"name":"envelope","config":{"mode":"protect"}}'; fi
  call PUT "/routes/$route/plugins/e0000000-0000-4000-8000-00000000${n}01" "$CORS"
  call PUT "/routes/$route/plugins/e0000000-0000-4000-8000-00000000${n}02" "$KEYAUTH"
  call PUT "/routes/$route/plugins/e0000000-0000-4000-8000-00000000${n}03" "$ENV"
done
echo "Done. Plain routes /api-a and /api-b are unchanged; encrypted routes are /secure/api-a and /secure/api-b."
