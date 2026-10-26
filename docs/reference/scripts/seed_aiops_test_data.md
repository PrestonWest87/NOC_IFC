# Script: `scripts/seed_aiops_test_data.py`

Creates deterministic synthetic SolarWinds-style records for AIOps workflow verification. Run it from the API/webhook image or another environment with the project dependencies and the intended `DATABASE_URL` configured.

```bash
python scripts/seed_aiops_test_data.py          # dry run; writes nothing
python scripts/seed_aiops_test_data.py --apply  # delete/recreate AIOTEST-prefixed records
```

## Behavior

- Uses a fixed `random.Random(20260814)` seed to derive coordinates for 20 Arkansas-named test locations.
- Defines 41 synthetic node-type/priority pairs covering the supported SolarWinds ontology and compatibility aliases.
- Without `--apply`, prints the planned counts and exits before opening the database.
- With `--apply`, deletes `SolarWindsAlert` rows whose `node_name` starts with `AIOTEST-` and monitored locations named `AIOTEST Site NN`, recreates those locations, then passes each generated SolarWinds-shaped dictionary to `src.webhook_listener.process_payload_background()`.
- The webhook processing path writes SolarWinds alert and timeline-event rows. The script's cleanup removes the matching test alerts and locations but does **not** remove matching timeline history; use the administrator-authorized timeline clear action only if that history also needs to be cleared.

## Safety boundary

The script writes to whichever database `DATABASE_URL` selects when `--apply` is provided. Use a disposable/test database and review that URL first. Test payloads include `AIOTEST-` markers and placeholder `.invalid` SolarWinds links; they do not contact SolarWinds.
