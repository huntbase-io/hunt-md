---
type: investigation
name: Weather to Slack
labels:
- hunt
- TODO-attack-technique
hypothesis: Fetches current temperature and humidity for a coordinate pair from Open-Meteo
  (no API key) and posts a one-line summary to a Slack incoming webhook. Uses the
  soarca-assignment / jq step extension to pull values out of the JSON response (Open-Meteo
  returns JSON; jq requires valid JSON input). The extracted values land as string-typed
  variables and are interpolated directly into the Slack message body.
parameters:
  lat:
    type: string
    default: '51.43940'
    description: Latitude as a decimal string (e.g. '51.43940' for Eindhoven). String-typed
      so it interpolates cleanly into the URL.
  lon:
    type: string
    default: '5.47789'
    description: Longitude as a decimal string (e.g. '5.47789' for Eindhoven).
  location_name:
    type: string
    default: Eindhoven
    description: Human-readable name of the location (used in the Slack text; Open-Meteo
      only takes coordinates).
  slack_webhook_path:
    type: string
    description: Path portion of the Slack incoming webhook, e.g. '/services/TXXX/BXXX/<token>'.
      Bind at trigger time; this is a secret. The command line is interpolated.
  soarca_http_api_result:
    type: string
    description: Raw response body from the weather call. jq runs against this.
  temp:
    type: string
    description: Temperature value extracted by jq (.current.temperature_2m). Always
      string-typed (the assignment engine forces string).
  humidity:
    type: string
    description: Humidity value extracted by jq (.current.relative_humidity_2m).
  unit:
    type: string
    description: Temperature unit extracted by jq (.current_units.temperature_2m,
      typically '°C').
targets:
  soarca-http-api:
    agent: true
    name: soarca-http-api
  open-meteo:
    category: http-api
    name: Open-Meteo
  slack-incoming-webhook:
    category: http-api
    name: Slack incoming webhook
x_cacao_source:
  id: playbook--460fda3e-11ba-4584-9dfa-ea3e5643c515
  spec_version: cacao-2.0
  created: '2026-05-27T10:00:00.000Z'
  created_by: identity--1a09b724-e562-41eb-a8c2-9acf4d4f1fcc
x_source:
  repo: https://github.com/COSSAS/SOARCA
  path: test/playbook/assignment-playbook.json
  license: Apache-2.0
  note: Converted from CACAO by `huntmd convert`; a draft, not a curated hunt.
---

# Weather to Slack

Fetches current temperature and humidity for a coordinate pair from Open-Meteo (no API key) and posts a one-line summary to a Slack incoming webhook. Uses the soarca-assignment / jq step extension to pull values out of the JSON response (Open-Meteo returns JSON; jq requires valid JSON input). The extracted values land as string-typed variables and are interpolated directly into the Slack message body.

## get-current-weather-open-meteo
```action target=soarca-http-api
GET /v1/forecast?latitude={{lat}}:value&longitude={{lon}}:value&current=temperature_2m,relative_humidity_2m HTTP/1.1
```
~~~yaml
cacao_id: action--4551c3d2-8e0d-47c5-9270-328194047a2b
command_type: http-api
~~~

## post-weather-summary-to-slack
```action target=soarca-http-api
POST {{slack_webhook_path}}:value HTTP/1.1
```
~~~yaml
cacao_id: action--44a5ed3d-b5f0-4fbc-ac9d-2c044d99debf
command_type: http-api
~~~
→ end
