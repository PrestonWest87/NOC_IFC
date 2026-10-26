# Route module: `src.api.routes.hunting`

Prefix: `/api/v1/hunting`. Every endpoint requires page permission `Threat Hunting & IOCs`.

| Method/path | Additional grants | Inputs and behavior |
|---|---|---|
| `GET /iocs?days_back=3&limit=1000` | `Tab: Threat Hunting -> Global IOC Matrix` | `days_back` 1–30; `limit` 1–1000. Returns recent extracted IOCs joined to source-article links; repeated CVE values are grouped with multiple sources. |
| `GET /osint-pivot?ioc_type=&ioc_value=` | Global IOC Matrix tab | Returns `{link}` for validated hash, IPv4, domain, CVE, or MITRE ATT&CK values; unsupported/malformed values return a null link. |
| `GET /search-articles?target=&days_back=3` | `Tab: Threat Hunting -> Deep Hunt Builder` | Target max 500 characters, quoted phrases must balance, at most 50 parsed terms; `days_back` is 1–30. Terms are ORed across title, summary, and full content; at most 30 rows are returned. |
| `GET /elastic-events?hours_back=24&page=1&page_size=100` | `Tab: Reporting -> Elastic SIEM Report` | `hours_back` 1–168, page 1–1000, `page_size` 1–500. Returns `{items,total,page,page_size,hours_back}` from the local Elastic cache. |
| `POST /sync-elastic-cache?hours_back=24` | Elastic SIEM tab + `Action: Manually Sync Data` | Synchronizes high-severity events using the shared worker. `hours_back` is 1–168; returns HTTP 502 on failure and 503 when skipped because `ELASTIC_URL` is blank. |
| `POST /generate-siem-triage` | Elastic SIEM tab + legacy `Action: Trigger AI Functions` | JSON `{events:[...]}` with 1–50 events. Input fields are bounded, extras ignored, and serialized size over 100 KB returns HTTP 413. Returns `{summary}` from the configured LLM. |

The Deep Hunt page builds its detection package in frontend code from the search result records. It does not call an LLM endpoint for that package; only the separate SIEM triage route makes an LLM request. See [`ThreatHuntingPage.md`](../../web/pages/ThreatHuntingPage.md) for the rendered flow.
