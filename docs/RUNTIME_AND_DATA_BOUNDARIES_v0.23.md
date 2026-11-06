# v0.23 — echte runtimevarianten, bronindex en distributiegrenzen

Peildatum: 2026-11-01. De tabel beschrijft **werkelijk lokaal uitgevoerde**
interpretervarianten, niet een vrijgegeven multiplatform-kwalificatie.

| Serie | Werkelijk geteste uitvoerbare runtimes | Bewijslimiet |
|---|---|---|
| Normale CPython | 3.9.25, 3.10.22, 3.11.17, 3.12.14, 3.13.16, 3.14.8, 3.15.0 | Eén Linux x86_64-build per minor, niet elke microversie |
| Free-threaded CPython | 3.13.16t, 3.14.8t, 3.15.0t | Werkelijke GIL-status en C11-atomic/native-lock-fixture; niet alle echte derdepartijwheels |
| PyPy | 3.9.19, 3.10.16, 3.11.17, 3.12.15 | Echte interpreter-/SOABI-identiteit; CPython-ABI-bewijs wordt niet hergebruikt |
| CPython pre-release | 3.15.0a1, 3.15.0b1, 3.15.0rc1, 3.16.0a1 | Aparte pre-releaseprobes; toekomstige algemene productkwalificatie niet gegarandeerd |

## Echte analytische DuckDB-engine

Voor dezelfde zeven reguliere CPython-interpreters zijn de volgende
**afzonderlijk geïnstalleerde** native DuckDB-wheels geïmporteerd en via SQL
uitgevoerd. Deze wheels bevinden zich in de privé-testomgeving en worden
**niet** meegeleverd in de source-/Rust-releasebundle.

| CPython | DuckDB | Werkelijk geteste onderdelen |
|---|---|---|
| 3.9 en 3.10 | 1.4.4 | Native connectie, getimede SQL-query's, persistente experimentdatabase |
| 3.11 t/m 3.15 | 2.0.0 | Native connectie, getimede SQL-query's, persistente experimentdatabase |

De projectcode kan een optioneel reeds geïnstalleerd DuckDB gebruiken, maar
claimt niet dat iedere toekomstige Python-versie meteen een compatibele
wheel heeft. `python/knowledge_scale_v23.py` geeft bij ontbrekende of
onvoldoende aangetoonde dependencies een expliciete `NOT_RUN` terug.

## Officiële PEP-index

`python/provenance_v23.py` heeft via de officiële HTTPS-bron
`https://peps.python.org/api/peps.json` **747 PEP-records** opgehaald,
SHA256 en de opgeslagen broninhoud vastgelegd en lokaal in SQLite FTS5
geïndexeerd. Een tweede echte HTTP-aanvraag controleerde ETag/304, waarna
de cache-inhoud opnieuw cryptografisch op SHA256 werd gecontroleerd.
Dit bewijst bronconsistentie en actuele bronopvraging op meetmoment, **geen**
automatische ondersteuning van iedere toekomstige feature of third-party API.

## Beveiligings- en productielimieten

- **F209 — externe OSV-audit:** officiële HTTPS-querybatch naar
  `api.osv.dev/v1/querybatch` controleerde elk van de 100 echte
  SBOM-componenten (67 Cargo-crates, 33 PyPI-distributies). De ruwe
  100-antwoorden-snapshot en de verzoek-/antwoord-SHA256 zijn gepind;
  een afzonderlijke, opnieuw gemeten SHA256 van de definitieve Rust-ELF
  beschermt tegen het hergebruiken van oud bewijs na rebuild. De Python
  auditor staat los van de Rust-binary om een circulaire zelf-hash te
  vermijden. De lokale verifierwheels zijn **optionele testafhankelijkheden**,
  geen onderdeel van de uitgeleverde Rust-binary. Gemelde advisories: nul
  op het meetmoment, maar uitgeversprovenance voor alle componenten blijft
  `UNKNOWN` en onbekende kwetsbaarheden worden niet uitgesloten.
- **F257 — procesgrenzen:** een echt lokaal op loopback afgeschermd
  Redis-7.2.11-serverproces en twee Celery-5.5.3-workers hebben 25
  afzonderlijke taken verwerkt en met Redis Streams gecorreleerd.
  Het geteste Redis-exemplaar en de installatiebundels zijn fixtures;
  dit bewijst geen productie-broker, clusterfailover of Windows-uitvoering.
- **F235 — modellen:** zelfgeleerde LSA en multinomiale Naive Bayes zijn
  gecontroleerd tegen 14 onafhankelijk gelabelde standaardbibliotheekqueries
  per minor. De kosteneenheid is werkelijk gemeten CPU-µs, **geen fictieve
  dollarkost**; p95-latentie en modelkwaliteit worden apart gemeten.
  Extern LLM-verbruik, onbegrensde codehersteltaken en productiebudgetten
  vallen buiten dit beperkte toepassingsdomein (F127 blijft open).
- Geen OS-bewezen runner voor willekeurige onbetrouwbare Python-code; geen
  hostnetwerk-/DNS-mountnamespace-isolatie bewezen.
- Echt lokaal ondertekende Rust-v0.22→v0.23-binary-activatie is met
  operator-SHA256-pin, werkelijke `--version`-canary en automatische
  pointer-rollback beproefd; er is geen officiële publisheridentiteit,
  download-/reboot-/multi-process-productie-updater of extern releasekanaal.
- De echte package-frameworkmatrix onderscheidt geïnstalleerde runtimes
  strikt van ontbrekende versies. Een geslaagde statische diagnose maakt
  een ontbrekende CUDA-/service-/framework-runtime niet `PASS`.
- De zes kwaliteitsassen en externe audits blijven afzonderlijke voorwaarden
  vóór iedere algemene productvrijgave. Een lokaal checklistvinkje is slechts
  een met echt bewijsmateriaal begrensde implementatie.
