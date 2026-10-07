---
name: rest-api-profil
description: Sweden's national REST API-profil and the RAP-LP lint tool. Use before designing or changing any HTTP interface meant for a Swedish public-sector consumer, before claiming any degree of conformance, and when deciding which of the profile's areas apply to something that is not a conventional resource API.
---

# The national REST API-profil

DIGG's recommendation for what a Swedish public-sector REST API should look like.
It is a *recommendation*, and it says so: choosing to follow it means meeting its
SKALL requirements, so there is no such thing as partial conformance. A partially
adopted profile is a named subset plus a recorded exception list — never
"conformant".

This file is house knowledge so that nobody re-derives which parts matter and
gets it wrong differently each time. What it is **not** is a substitute for
reading the profile when a rule is load-bearing.

## Versions, and the gap between them

| Thing | Version | Date |
| ----- | ------- | ---- |
| The profile | 2.0.0 | 2026-06-17 |
| RAP-LP, the lint tool | 2.0.0 | 2026-06-16 |
| The profile RAP-LP v2.0.0 says it checks | **1.2.0** | — |

**Read that third row before trusting a green run.** RAP-LP v2.0.0 was released
the day *before* profile 2.0.0, and its own `GUIDELINES.md` states
*"Denna version av RAP-LP är kompatibel med REST API-profil version 1.2.0"*. So
the tool passing is evidence about profile 1.2.0, and the delta to 2.0.0 is
unchecked by anything. Saying "RAP-LP is green, therefore we follow the profile"
is the specific mistake this table exists to prevent.

- The profile: <https://www.dataportal.se/rest-api-profil>
- The tool and its rules: <https://github.com/diggsweden/rest-api-profil-lint-processor>
  and [GUIDELINES.md](https://github.com/diggsweden/rest-api-profil-lint-processor/blob/main/GUIDELINES.md)

Re-check both versions before relying on this file. A later version is visibly a
later version only if somebody looks.

## SKALL, BÖR, KAN

The profile uses RFC 2119 keywords in Swedish. The mapping is exact, and the
consequence differs:

| Profile | RFC 2119 | What it means for us |
| ------- | -------- | -------------------- |
| SKALL | MUST | Meet it, or do not claim to follow the area |
| SKALL INTE | MUST NOT | Same, inverted |
| BÖR | SHOULD | Depart from it only with a reason recorded in a bead |
| BÖR INTE | SHOULD NOT | Same, inverted |
| KAN | MAY | Free choice; no exception needs recording |

Keep the Swedish keyword when quoting a rule. Translating normative text is how a
SKALL quietly becomes a BÖR.

## What applies to this proxy, and what does not

The decision is **`gc-4oo.2`**, not this file — this only says where to look and
why the question is not obvious.

This product is a webhook *receiver* with two endpoints, whose inbound contract
is owned by whoever sends to it. Large parts of a profile written for resource
APIs therefore have nothing to say about it:

- **RES, UFN, MOG, FNS** — resources, URL naming, maturity, filtering and
  pagination. There is no resource collection here; there are two endpoints that
  accept a body and answer with a status.
- **The Webhooks chapter's producer requirements** — re-send and consumer
  onboarding bind a producer offering webhooks to registered consumers. Reading
  them as ours would contradict the delivery promise in README, which only the
  Durable delivery epic may change.

What plausibly does apply: **DOK** (there is no machine-readable description of
the interface yet), **FEL** (what a refusal looks like), **SAK** (the
authentication boundary is the whole point of this product), **SPA**
(correlation — a `DeliveryId` already exists and is logged), **VER**, **AME**,
**ARQ**, **DOT**.

Do not turn that paragraph into conformance claims. It is a reading list.

## Running RAP-LP locally

Prefer the container: the npm package lives in GitHub Packages and needs a
personal access token, which is friction for no benefit.

```bash
podman run --rm -v "$(pwd):/data" \
  ghcr.io/diggsweden/rest-api-profil-lint-processor:v2.0.0 -f /data/openapi.yaml
```

`docker` in place of `podman` works identically. Pin the version rather than
using a floating tag — the rule set is part of the tool, so an unpinned tag means
the checks change under you.

## The rules RAP-LP checks

54 rules across 13 areas. **FOR is the tool's own area, not the profile's**: its
rules are established good practice that the profile does not require, so a FOR
failure is advice, not non-conformance.

Each requirement is quoted verbatim in Swedish because it is normative text. The
area headings are translated for navigation only.

### DOK — Documentation

*Dokumentation*, 12 rules checked.

- **DOK.01** · BÖR · I regel BÖR dokumentationen och specifikationen för ett API finnas allmänt tillgänglig online.
- **DOK.03** · SKALL · Dokumentationen av ett API SKALL innehålla övergripande information om API:et.
- **DOK.06** · BÖR · Dokumentationen BÖR finnas på både svenska och engelska.
- **DOK.07** · BÖR · Dokumentationen av ett API BÖR innehålla övergripande information om API:et.
- **DOK.08** · SKALL · Ett API:s servicenivå SKALL finnas tydligt beskriven i dokumentationen.
- **DOK.09** · SKALL · Kända problem och begränsningar SKALL finnas tydlig beskrivna i dokumentationen.
- **DOK.11** · SKALL · Avsikten och beteendet hos API:et SKALL beskrivas så utförligt och tydligt som möjligt.
- **DOK.15** · SKALL · I dokumentationen av API:et SKALL exempel på API:ets fråga (en:request) och svar (en:reply) finnas i sin helhet.
- **DOK.17** · BÖR · API-specifikation BÖR dokumenteras med den senaste versionen av OpenAPI Specification.
- **DOK.19** · SKALL · Ett API:s resurser och de möjliga operationer som kan utföras på resursen SKALL beskrivas så utförligt och tydligt som möjligt.
- **DOK.20** · SKALL · Förväntade returkoder och felkoder SKALL vara fullständigt dokumenterade.
- **DOK.21** · SKALL · Krav på autentisering SKALL anges i specifikationen.

### DOT — Date and time formats

*Datum- och tidsformat*, 2 rules checked.

- **DOT.02** · SKALL · Datum och tid SKALL (DOT.02) anges enligt [RFC 3339](https://datatracker.ietf.org/doc/html/rfc3339) som bygger på ISO-8601.
- **DOT.04** · SKALL · Datum och tid SKALL hanteras enligt följande, använd alltid RFC 3339 för datum och tid, acceptera alla tidszoner i API:er returnera datum och tid i UTC och använd inte tidsdelen om du inte behöver den.

### RES — Resources

*Resurser*, 2 rules checked.

- **RES.02** · BÖR · Primärnycklar eller personligt identifierbar information (personnummer, etc.) BÖR INTE exponeras.
- **RES.06** · SKALL · Resurser SKALL följa den namnsättningskonvention som beskrivs för URL:er, det vill säga att resurser anges med gemener, använder endast alfanumeriska tecken och bindestreck för att separera eventuella ord.

### UFN — URL format and naming

*URL Format och namngivning*, 6 rules checked.

- **UFN.01** · BÖR · En URL för ett API BÖR
- **UFN.02** · SKALL · Alla API:er SKALL exponeras via HTTPS på port 443.
- **UFN.05** · BÖR · En URL BÖR INTE vara längre än 2048 tecken.
- **UFN.07** · SKALL · URL:n SKALL använda dessa tecknen a-z, 0-9, "-", "." samt "~", se vidare i RFC 3986).
- **UFN.08** · SKALL · Endast bindestreck '-' SKALL användas för att separera ord för att öka läsbarheten samt förenkla för sökmotorer att indexera varje ord för sig.
- **UFN.09** · SKALL · Blanksteg ' ' och understreck '\_' SKALL INTE användas i URL:er med undantag av parameter-delen.

### MOG — Maturity

*Mognad*, 2 rules checked.

- **MOG.01** · SKALL · Alla API:er SKALL designas för att uppnå nivå 2 enligt Richardson Maturity Model.
- **MOG.02** · BÖR · Alla API:er BÖR designas för att uppnå nivå 3 enligt Richardson Maturity Model.

### AME — API message

*API Message*, 5 rules checked.

- **AME.01** · BÖR · Datamodellen för en representation BÖR (AME.01) beskrivas med JSON enligt senaste versionen, RFC 8259.
- **AME.02** · BÖR · Det BÖR förutsättas att alla request headers som standard använder 'Accept' med värde 'application/json'.
- **AME.04** · BÖR · För fältnamn i request och response body BÖR camelCase eller snake_case notation användas.
- **AME.05** · SKALL · Inom ett API SKALL namnsättningen vara konsekvent, dvs blanda inte camelCase och snake_case.
- **AME.07** · BÖR · Fältnamn BÖR använda tecken som är alfanumeriska.

### ARQ — API request

*API Request*, 3 rules checked.

- **ARQ.01** · BÖR · Ett request BÖR skickas i UTF-8.
- **ARQ.03** · BÖR · Alla API:er BÖR supportera följande request headers: Accept, Date, Cache-Control, ETag, Connection och Cookie.
- **ARQ.05** · SKALL · Payload data SKALL INTE användas i HTTP-headers.

### FEL — Error handling

*Felhantering*, 2 rules checked.

- **FEL.01** · SKALL · Om HTTP svarskoderna inte räcker SKALL API:et beskriva feldetaljer enligt RFC 9457 med dessa ingående attribut: 'type', 'title', 'status', 'detail', 'instance'.
- **FEL.02** · SKALL · Schemat enligt RFC 9457 bör innehålla de beskrivna attributen i FEL.01 och SKALL använda mediatypen `application/problem+json` eller `application/problem+xml` i svaret.

### VER — Versioning

*Versionhantering*, 2 rules checked.

- **VER.05** · BÖR · Version BÖR anges i URL enligt formatet v[x] där 'v' avser förkortning för version och x avser ett och bara ett nummer (0-n) för major-version.
- **VER.06** · SKALL · Information om ett API SKALL tillgängliggöras via resursen `api-info` under roten till API:et.

### SPA — Traceability and correlation

*Spårbarhet och korrelation*, 3 rules checked.

- **SPA.02** · SKALL · API-producenter SKALL (SPA.02) acceptera HTTP-headern traceparent i inkommande anrop och propagera spårningsinformationen vidare enligt W3C Trace Context vid vidare anrop till andra system..
- **SPA.04** · BÖR · API-producenten BÖR (SPA.04) inkludera HTTP-headern traceparent i ett API-svar.
- **SPA.07** · SKALL INTE · Alternativa identifierare, såsom x-request-id, KAN användas som komplement för interna behov, men SKALL INTE ersätta traceparent vid spårning av API-anrop mellan system och organisationer.

### FNS — Filtering, pagination and search

*Filtrering, paginering och sökparametrar*, 7 rules checked.

- **FNS.01** · SKALL · Parameternamn SKALL anges med en konsekvent namnkonvention inom ett API, exempelvis antingen snake_case eller camelCase.
- **FNS.03** · SKALL · Sökparametrar SKALL starta med en bokstav.
- **FNS.05** · BÖR · Sökparametrar BÖR vara frivilliga..
- **FNS.06** · BÖR · Sökparametrar BÖR använda tecken som är URL-säkra (tecknen A-Z, a-z, 0-9, '-', '.', '\_' samt '~', se vidare i RFC 3986).
- **FNS.07** · SKALL · Vid användande av paginering, SKALL följande parametrar ingå i request: 'limit' och någon av 'page' eller 'offset'.
- **FNS.08** · SKALL · 'page' SKALL alltid starta med värde 1
- **FNS.09** · BÖR · Defaultvärde för limit BÖR vara 20

### SAK — Security

*Säkerhet*, 7 rules checked.

- **SAK.01** · SKALL · All transport SKALL ske över HTTPS med minst TLS 1.2.
- **SAK.09** · SKALL · Basic- eller Digest-autentisering SKALL INTE användas.
- **SAK.10** · SKALL · Authorization: Bearer header SKALL användas för autentisering/auktorisation.
- **SAK.15** · SKALL · API-nycklar SKALL INTE inkluderas i URL eller querysträngen.
- **SAK.16** · SKALL · API-nycklar SKALL inkluderas i HTTP-headern eftersom querysträngar kan sparas av klienten eller servern i okrypterat format av webbläsaren eller serverapplikationen.
- **SAK.18** · BÖR · OAuth version 2.0 eller senare BÖR användas för auktorisation.
- **SAK.29** · BÖR · Man BÖR respektera angiven Content-Type i header. Förfrågningar som innehåller oväntade eller saknade Content-Type headers bör avvisas med HTTP-status 415 Unsupported Media Type.

### FOR — Preconditions (the tool's own, not the profile's)

*Förutsättningar*, 1 rules checked.

- **FOR.02** · SKALL · EN GET -förfrågan SKALL INTE acceptera en body.

## When a rule bites

The rules point at parts of an OpenAPI specification via JSONPath Plus
expressions, which `GUIDELINES.md` gives per rule along with an explanation and
an example. Read that entry rather than inferring the requirement from the one
line above — these lines exist to tell you *which* rule to go and read.
