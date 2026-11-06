# Complete functiechecklist — Rust Python Healer

Peildatum: **2026-11-06**. Startpunt: werkelijk geïnspecteerde projectcode
v0.6, in v0.7 uitgebreid vanuit elf aanvullende technische invalshoeken. Deze checklist is het centrale **ontwikkelregister**; een nieuwe
feature krijgt eerst een uniek nummer en testcriteria. Geen bewijs = geen PASS.

**Betekenis:** `[x] IMPLEMENTED_TESTED` betekent alleen dat de functie in
de huidige code bestaat én op gecontroleerde fixtures is getest; dit is
geen productiekwalificatie. `[ ] PARTIAL` betekent beperkte implementatie,
`NOT_IMPLEMENTED` ontbreekt, `NOT_RUN` heeft nog geen uitvoering/bewijs en
`BLOCKED` vereist een ontbrekende veilige voorziening of bevoegdheid.

**Referentiebewijs:** `evidence/VALIDATION_v0.26.md`, `evidence/VALIDATION_v0.25.md` en `evidence/VALIDATION_v0.24.md`, aangevuld met de onveranderde v0.23-baseline in `evidence/VALIDATION_v0.23.md` (en v0.22, v0.21, v0.20 en v0.19 als historische baselines) en het afzonderlijke
offline regressiebewijs per CPython-minor 3.9–3.15. De uitvoer van onbekende
projectcode en netwerkafhankelijke volledige kwalificatie blijven buiten scope.

### Actuele ontwikkelstand — Windows-uitwerking 2026-11-06

**235/260 IMPLEMENTED_TESTED; 25 open.** R8 sluit F230 af met 1.050.000 unieke,
herleidbaar echte Engelstalige documentdelen, vijf verse Windows-meetprocessen
en de werkelijke getypeerde Rust-entrypoint. Herkomst, inputbeveiliging,
metingen en integratie zijn afzonderlijk beoordeeld: `evidence/windows_r8/F230/`.
Dit is generieke FTS-schaalmeting; geen semantische/ANN- of Python-API-relevantieclaim.
R8 sluit daarnaast F167 af voor het oorspronkelijke
Windows-methodencontract: zeven stabiele minors en een echte, primair
geverifieerde Python 3.16.0a1, inclusief IPC, fout-/timeoutopruiming,
unsupported-methoden en afzonderlijke onafhankelijke veiligheidsreview.
Bewijs: `evidence/windows_r8/F167/contract.json` en `independent-review.json`.
Dit kwalificeert geen toekomstige stabiele 3.16 (F046), externe audit (F110)
of gehele productrelease (F114). Eerdere HOLD/FAIL-records blijven behouden.
F253 en F254 zijn na implementatie,
positieve/negatieve tests en afzonderlijke bron-/bewijsreview afgetekend.
F253: Torch 2.11.0+cu128, CPython 3.12.16, Windows CPU/CUDA12.8, eigen
legacy-/ZIP-checkpoints met weights_only en map_location=cpu.
F254: TensorFlow 2.21.0 en JAX/jaxlib 0.12.0.1, native Windows CPU en de
geautoriseerde WSL2-GPU-route, inclusief echte graph/XLA/JIT-uitvoering.
Module-/oracle-regressies zijn op alle zeven CPython-minors uitgevoerd.
Bewijs en onafhankelijke ontwikkelreview: `evidence/windows_v029/`.
R6 tekent daarnaast F145 af voor de lokale Windows 11 Home x64-build en
geselecteerde positieve/negatieve runtimefixtures: zie
`evidence/windows_r6/CORE_VALIDATION.json`. De zeven onveranderde brede R6-runs
bevatten 31 FAIL-events op 17 verschillende testgevallen; alle 17 kregen
passende gerichte PASS-hertests. R7 bevat de Windows-handtekening- en
frameworkintegraties en bindt de lokale build aan
`evidence/windows_r7/CORE_VALIDATION.json`. De volledige R7-run op CPython
3.14.10 registreerde 2.438 PASS, 79 NOT_RUN en drie FAIL-records: uitsluitend
het hulpregister dat F145 nog als open verwachtte. Na de beoordeelde correctie
slagen alle negen hulpregistertests op alle zeven minors: 63/63 PASS.
De oorspronkelijke brede FAIL blijft bewaard; een volledige brede herhaling
na alleen deze registercorrectie is NOT_RUN. Externe CI en de productierelease
blijven open.
De 230 eerdere vinkjes blijven historisch afgebakend fixturebewijs. De brede
Windows-regressies bevatten hun historische FAIL-uitkomsten; dit is geen
volledige Windows- of productrelease.

**Historische stand v0.26-bronuitbreiding: 230/260 bewezen, 30 expliciet open.** De veilige en echt
getrainde F127-codeherstelmodelrouter is uitgebreid en op zeven minors
getest, maar voor willekeurige bugs blijft F127 `PARTIAL`. Er worden geen
nieuwe checklistvinkjes toegekend door alleen het aantal tests te verhogen.
F050, F135, F150, F241 en F247 zijn inmiddels van `NOT_IMPLEMENTED` naar `PARTIAL`
gegaan: echte deelimplementaties zijn getest, maar hun volledige eis is niet
geleverd. F207 en F239 blijven `PARTIAL` ondanks nieuwe privacyredactie en
lokale eenmalig ondertekende mutatiegoedkeuring.

### Vastgelegd Windows-only doelplatform (v0.28-kandidaat)

De gebruiker heeft **Windows 11 Home x64 (Intel/AMD), NVIDIA** en
**geautomatiseerde Windows-tests** gekozen. De oorspronkelijke 260 F-ID's
blijven behouden. macOS (F146/F177) en ARM64 buiten dit doel zijn
`OUT_OF_SCOPE_NOT_A_PASS`; ze worden dus **niet** kunstmatig afgevinkt.
De bestaande Linux-v0.27-uitvoeringen blijven historische ontwikkelbewijzen,
geen Windows-kwalificatie. De nieuwe Windows CI-workflow is geschreven,
een externe Windows CI-run blijft `NOT_RUN`; de echte lokale Windows 11
Home-runs zijn uitgevoerd en de brede suites blijven `FAIL`. De standaard `windows-2025`-runner gebruikt Windows Server
2025, niet Windows 11 Home. NVIDIA/GPU-tests vereisen een apart geverifieerde
hardware-runner. Zie `windows_qa/windows_scope.json` en
`docs/WINDOWS_ONLY_v028.md`.

### Prioriteiten en toelatingseisen

- **P0 — blokkades eerst:** veilige sandbox, projectregressie, secrets,
  supply-chain-provenance, herstelvergelijking en herhaalbare rollback
  (onder meer F039, F107–F110, F190–F200, F201–F210).
- **P1 — volwaardige debugger en compatibiliteit:** runtime-breakpoints,
  DAP, asyncio, free threading, subinterpreters, PEP 508 en pylock
  (F011–F020, F057–F060, F151–F190).
- **P2 — brede kennis, schaal en integratie:** vectorzoeklaag,
  database-operaties, agentorkestratie, UX en domeinspecifieke adapters
  (F067–F080, F121–F140, F211–F260).

Voordat een nieuw item naar `IMPLEMENTED_TESTED` mag: **(1)** werkende
code met versie- en bronregistratie, **(2)** positieve én negatieve
regressietests, **(3)** uitvoer op relevante echte CPython-versies en
**(4)** een afzonderlijke veiligheidsbeoordeling bij uitvoering of mutatie
van niet-vertrouwde code. Bewijs-ID's horen in de versievalidatie.
Volledige productkwalificatie vereist bovendien alle zes kwaliteitsassen
PASS; een checklistvinkje is op zichzelf niet voldoende.

### Waarom de open punten nog niet zijn afgevinkt

**Elk niet-afgevinkt F-nummer heeft direct onder de checklistregel een
`Reden:`-regel.** De broncode-audit weigert voortaan ontbrekende redenen;
een statuswijziging vereist ook het bijwerken van die uitleg.

| Blokkade of ontbrekend bewijs | Relevant voor | Actie vóór PASS |
|---|---|---|
| WSL2 kan echte namespaces en een afgeschermd prototype uitvoeren; algemene projectintegratie en onafhankelijke kwalificatie ontbreken | F039, F107–F108, F204–F206 | Productintegratie, volledige adversariële controle, gezamenlijke resourcegrenzen en passende onafhankelijke veiligheidsreview |
| Productie-uitgeversidentiteit en automatische binaire distributie ontbreken; lokale ondertekende échte Rust-binary-canary/rollback is wel getest | F090, F150 (F148/F149/F246/F250 alleen lokale fixtures) | Onafhankelijke vertrouwde uitgeverssleutels, externe provenance, veilige productie-uitrol en expliciete releasebevoegdheid |
| Externe runners en bepaalde alternatieve platforms ontbreken; CPython-t en PyPy zijn wél lokaal getest | F046, F110, F134, F146–F147, F176–F177, F248 | Echte uitvoeringen op betreffende interpreter, OS of onafhankelijk auditsysteem |
| Veiligheid en volledigheid van willekeurige projecten zijn niet aangetoond; geselecteerde debugger- en herstelhandelingen zijn alleen op vaste fixtures bewezen | F114, F191–F210 en nog openstaande F-ID's rond F010–F030 (F128 slechts lokale gates) | Geïsoleerde projectregressie, extern onafhankelijke oracle en zes vooraf vastgelegde kwaliteitsassen |
| Overige code, brondata, schaal- of regressiebewijzen ontbreken | Andere niet-afgevinkte F-ID's | Implementeer de genoemde functie, voer positieve/negatieve versiechecks uit en registreer bewijs |

## 1. CLI, diagnose en foutmeldingen

- [x] F001 Python-bron compile-only controleren — IMPLEMENTED_TESTED
- [x] F002 SyntaxError-lijn, kolom en fouttype rapporteren — IMPLEMENTED_TESTED
- [x] F003 Ontbrekende en te grote invoerbestanden afwijzen — IMPLEMENTED_TESTED
- [x] F004 Projectmap parallel op `.py`-bestanden scannen — IMPLEMENTED_TESTED
- [x] F005 Virtuele omgevingen en buildmappen negeren — IMPLEMENTED_TESTED
- [x] F006 Scanlimieten en lege scan zonder valse PASS afhandelen — IMPLEMENTED_TESTED
- [x] F007 Gestructureerde JSON-diagnose teruggeven — IMPLEMENTED_TESTED
- [x] F008 Opgeslagen tracebacks naar frames en exceptions ontleden — IMPLEMENTED_TESTED
- [x] F009 Gekoppelde exceptions en SyntaxError-tracebacks herkennen — IMPLEMENTED_TESTED
- [x] F010 Suggesties inhoudelijk onafhankelijk valideren — IMPLEMENTED_TESTED

## 2. Interactieve runtime-debugger

- [x] F011 Breakpoints plaatsen, in- en uitschakelen — IMPLEMENTED_TESTED
- [x] F012 Voorwaardelijke breakpoints en hitcounts — IMPLEMENTED_TESTED
- [x] F013 Step-in, step-over, step-out en continue — IMPLEMENTED_TESTED
- [x] F014 Post-mortem-debugging van een vastgelopen proces — IMPLEMENTED_TESTED
- [x] F015 Lokale en globale variabelen in stackframes inspecteren — IMPLEMENTED_TESTED
- [x] F016 Watch-expressies veilig evalueren — IMPLEMENTED_TESTED
- [x] F017 Call-stack navigeren, threads en async-taken bekijken — IMPLEMENTED_TESTED
- [x] F018 Exceptions realtime pauzeren en onderscheppen — IMPLEMENTED_TESTED
- [x] F019 `sys.settrace`-backend voor legacy Python-versies — IMPLEMENTED_TESTED
- [x] F020 `sys.monitoring`-backend vanaf Python 3.12 — IMPLEMENTED_TESTED

## 3. Automatisch herstellen en herschrijven

- [x] F021 Veilige Ruff-autofixes in afzonderlijke kandidaat uitvoeren — IMPLEMENTED_TESTED
- [x] F022 Conservatieve ontbrekende-dubbelepuntreparatie — IMPLEMENTED_TESTED
- [x] F023 Origineel nooit overschrijven en kandidaat afzonderlijk opslaan — IMPLEMENTED_TESTED
- [x] F024 Unieke variant-ID op code- en configuratiehash — IMPLEMENTED_TESTED
- [x] F025 Dubbele meting vóór tests herkennen — IMPLEMENTED_TESTED
- [x] F026 Expliciete `RETEST` opnieuw registreren — IMPLEMENTED_TESTED
- [x] F027 AST/CST-herschrijvingen met behoud van opmaak en comments — IMPLEMENTED_TESTED
- [x] F028 Meerdere onafhankelijke reparatiestrategieën laten concurreren — IMPLEMENTED_TESTED
- [x] F029 Complexe semantische fouten en API-migraties herstellen — IMPLEMENTED_TESTED
- [x] F030 Herstelpromotie alleen na bewezen gedragsequivalentie — IMPLEMENTED_TESTED

## 4. Functionele tests en regressie

- [x] F031 Precies 100 geselecteerde Python-cases per minorversie — IMPLEMENTED_TESTED
- [x] F032 700 curatiemetingen op echte CPython 3.9–3.15 — IMPLEMENTED_TESTED
- [x] F033 Versiegebonden end-to-end CLI-functiematrix — IMPLEMENTED_TESTED
- [x] F034 Python-helpertests onder alle zeven beschikbare interpreters — IMPLEMENTED_TESTED
- [x] F035 Rust-unit- en CLI-integratietests uitvoeren — IMPLEMENTED_TESTED
- [x] F036 Ruff-herstel en cache-/RETEST-integratie controleren — IMPLEMENTED_TESTED
- [x] F037 Valideren dat compile-only tests doelcode niet uitvoeren — IMPLEMENTED_TESTED
- [x] F038 Ontbrekende toekomstige interpreter als `NOT_RUN` markeren — IMPLEMENTED_TESTED
- [ ] F039 Volledige project-unit- en regressiesuite in veilige sandbox — BLOCKED
  - Reden: R6 bewijst echte WSL2-namespaces en vaste afgeschermde probes, maar de volledige project-unit-/regressierunner is nog niet geïntegreerd of onafhankelijk voor onbekende projectcode gekwalificeerd. Historische EPERM is niet de actuele capabilitystatus.
- [x] F040 Property-, fuzz-, mutation- en metamorfische tests — IMPLEMENTED_TESTED

## 5. Python-versies, taalkenmerken en platform-ABI

- [x] F041 Werkelijke CPython-implementatie en minorversie controleren — IMPLEMENTED_TESTED
- [x] F042 Python 3.9-afwijkende SyntaxError-tekst correct verwerken — IMPLEMENTED_TESTED
- [x] F043 Versiegebonden syntaxkenmerken 3.10–3.15 testen — IMPLEMENTED_TESTED
- [x] F044 Geselecteerde standaardbibliotheekfuncties per versie testen — IMPLEMENTED_TESTED
- [x] F045 Een nieuwe stabiele minorversie automatisch in matrix plannen — IMPLEMENTED_TESTED
- [ ] F046 Een échte toekomstige 3.16-interpreter volledig kwalificeren — NOT_RUN
  - Reden: Vier officiële Windows-previewbuilds zijn uitgevoerd: alpha/beta/RC 3.15 en 3.16.0a1 met 400 taalchecks en 32 grammar-oracles. Stabiele 3.16, de volledige pakket-/native-/platformmatrix en onafhankelijke productieoracle ontbreken.
- [x] F047 Alpha-, bèta- en releasecandidateversies apart testen — IMPLEMENTED_TESTED
- [x] F048 EOL- en securitysupport-waarschuwingen in CLI — IMPLEMENTED_TESTED
- [x] F049 Wheel-, native extension-, OS- en Python-ABI-matrix — IMPLEMENTED_TESTED
- [ ] F050 Alle ondersteunde microversies automatisch testen — PARTIAL
  - Reden: Zeven exacte Windows CPython-patches 3.9.25–3.15.2 zijn getest, met aanvullend bestaand 3.15.1-taalbewijs en expliciete lokale bytecodereferenties. Alle andere ondersteunde microversies, volledige native-wheelcombinaties en platformautomatisering zijn niet integraal bewezen.

## 6. Packages, dependencies en omgevingen

- [x] F051 Geïnstalleerde distributiemetadata zonder imports inspecteren — IMPLEMENTED_TESTED
- [x] F052 Eenvoudige `Requires-Python`-voorwaarden beoordelen — IMPLEMENTED_TESTED
- [x] F053 Onverenigbare Python-versievoorwaarden melden — IMPLEMENTED_TESTED
- [x] F054 Ontbrekende packages expliciet als `MISSING` melden — IMPLEMENTED_TESTED
- [x] F055 Ambigue dubbele distributies herkennen — IMPLEMENTED_TESTED
- [x] F056 Package-metadata naar de lokale kennisindex importeren — IMPLEMENTED_TESTED
- [x] F057 Volledige PEP 440-versiesemantiek uitvoeren — IMPLEMENTED_TESTED
- [x] F058 PEP 508-markers, extras en platformvariabelen evalueren — IMPLEMENTED_TESTED
- [x] F059 Transitive dependency- en conflictresolver — IMPLEMENTED_TESTED
- [x] F060 Importgrafiek, `pyproject.toml` en lockfiles analyseren — IMPLEMENTED_TESTED

## 7. Python-regels, bibliotheken en documentatie

- [x] F061 Handmatig versie- en brongebonden documenten toevoegen — IMPLEMENTED_TESTED
- [x] F062 Documentatie via FTS5 doorzoeken — IMPLEMENTED_TESTED
- [x] F063 Geïndexeerde documenten en packages tellen — IMPLEMENTED_TESTED
- [x] F064 Bron-URL, packageversie en SHA256 bewaren — IMPLEMENTED_TESTED
- [x] F065 Officiële Python-What's-New-documenten importeren — IMPLEMENTED_TESTED
- [x] F066 Geselecteerde PyPI-package-metadata bijwerken — IMPLEMENTED_TESTED
- [x] F067 Alle relevante PEP's met versie en status indexeren — IMPLEMENTED_TESTED
- [x] F068 Python-standaardbibliotheek-API's automatisch extraheren — IMPLEMENTED_TESTED
- [x] F069 Package-API's, signatures, deprecations en changelogs indexeren — IMPLEMENTED_TESTED
- [x] F070 Bronlicenties en inhoudsherkomst per document auditen — IMPLEMENTED_TESTED

## 8. Databases en kenniszoekmachine

- [x] F071 SQLite FTS5-kennisdatabase beheren — IMPLEMENTED_TESTED
- [x] F072 Full-text index via SQL-triggers synchroon houden — IMPLEMENTED_TESTED
- [x] F073 SQLite-variant- en evaluatieregister beheren — IMPLEMENTED_TESTED
- [x] F074 Content- en configuratiehashes berekenen en bewaren — IMPLEMENTED_TESTED
- [x] F075 Duplicaten op variantidentiteit weren — IMPLEMENTED_TESTED
- [x] F076 Evaluatiegegevens uitlezen en aggregaten tonen — IMPLEMENTED_TESTED
- [x] F077 Vectorzoekmachine voor semantische retrievalidatie — IMPLEMENTED_TESTED
- [x] F078 Dependency-/callgraph-database met versieedges — IMPLEMENTED_TESTED
- [x] F079 Analytische DuckDB-benchmarkdatabase — IMPLEMENTED_TESTED
- [x] F080 Automatische databasebackups, migratie en herstel — IMPLEMENTED_TESTED

## 9. Kennis- en software-updates

- [x] F081 Stabiele Python-release via officiële bron ontdekken — IMPLEMENTED_TESTED
- [x] F082 Updatecontrole zonder bestandswijzigingen — IMPLEMENTED_TESTED
- [x] F083 Documentatie- en metadata-updates toepassen — IMPLEMENTED_TESTED
- [x] F084 Verse en verlopen 24-uurs TTL controleren — IMPLEMENTED_TESTED
- [x] F085 ETag en ongewijzigde broninformatie verwerken — IMPLEMENTED_TESTED
- [x] F086 Python-versiemanifest atomair bijwerken — IMPLEMENTED_TESTED
- [x] F087 Foutieve update mag manifest niet vooruitzetten — IMPLEMENTED_TESTED
- [x] F088 Nieuwe Python 3.16-versie met testmocks detecteren — IMPLEMENTED_TESTED
- [x] F089 Continue `--watch`-updater end-to-end kwalificeren — IMPLEMENTED_TESTED
- [ ] F090 Rust-binary zelfupdate met handtekening en rollback — BLOCKED
  - Reden: Native Windows Rust-build, PE32+/AMD64-controles en runtimefixtures zijn daadwerkelijk PASS. De automatische PE-selfupdate met onafhankelijk vertrouwde uitgever/Authenticode, productieprocesvervanging, versie-CAS en rollback is niet gebouwd of gekwalificeerd; Linux-ELF-bewijs blijft afzonderlijk.

## 10. Statische analyse en foutoorzaken

- [x] F091 Volledig AST/CST-model van code met bronposities — IMPLEMENTED_TESTED
- [x] F092 Type-inferentie en typefouten over modules — IMPLEMENTED_TESTED
- [x] F093 Mypy/Pyright op projecteigen typeconfiguratie draaien — IMPLEMENTED_TESTED
- [x] F094 Ruff-afwijkingen in veilige autofixroute verwerken — IMPLEMENTED_TESTED
- [x] F095 Dependencies op kwetsbaarheden en advisories controleren — IMPLEMENTED_TESTED
- [x] F096 Security- en code-smellregels classificeren — IMPLEMENTED_TESTED
- [x] F097 Control-flow- en callgraph construeren — IMPLEMENTED_TESTED
- [x] F098 Dode code, ongebruikte variabelen en onbereikbare branches vinden — IMPLEMENTED_TESTED
- [x] F099 Datastromen, mutaties en aliasing volgen — IMPLEMENTED_TESTED
- [x] F100 Verouderde externe API-aanroepen lokaliseren — IMPLEMENTED_TESTED

## 11. Veiligheid en sandbox

- [x] F101 Python-helpers geïsoleerd met `-I -S -B` uitvoeren — IMPLEMENTED_TESTED
- [x] F102 Subprocessuitvoer en logs begrenzen — IMPLEMENTED_TESTED
- [x] F103 Subprocessen op timeout afbreken — IMPLEMENTED_TESTED
- [x] F104 Onbekende doelcode niet laten uitvoeren bij statische controle — IMPLEMENTED_TESTED
- [x] F105 Projectscans volgen geen symlinks naar externe bestanden — IMPLEMENTED_TESTED
- [x] F106 Herstelkandidaat in aparte stagingfile bewaren — IMPLEMENTED_TESTED
- [ ] F107 Echte container-/VM-sandbox voor willekeurige Python-code — BLOCKED
  - Reden: R6 heeft een werkelijk uitgevoerd WSL2/bubblewrap-prototype met zeven namespaces, uitsluitend toegelaten syscalls en een primair geverifieerde private Linux-runtime. Dit bewijst vaste probes; algemene onbekende-projectintegratie, volledige adversariële audit en gezamenlijke resourcekwalificatie ontbreken.
- [ ] F108 Netwerktoegang van testproces afdwingen blokkeren — BLOCKED
  - Reden: Vaste WSL2-probes tonen daadwerkelijke weigering van netwerk-/DNS- en directe syscallpogingen. De netwerkgrens is nog niet als algemeen projecttestpad geïntegreerd en onafhankelijk gekwalificeerd.
- [x] F109 Per test CPU-, RAM-, I/O- en schrijflimieten afdwingen — IMPLEMENTED_TESTED
- [ ] F110 Onafhankelijke sandbox- en supply-chainbeveiligingsaudit — NOT_RUN
  - Reden: Een onafhankelijke audit van sandbox, packages en supply chain is niet uitgevoerd; eigen tests gelden niet als externe audit.

## 12. Prestaties, bewijs en betrouwbaarheid

- [x] F111 Compilatietijd per evaluatie loggen — IMPLEMENTED_TESTED
- [x] F112 PASS/FAIL/NOT_RUN-velden in bewijsregistratie — IMPLEMENTED_TESTED
- [x] F113 Variantsamenvatting en bronhash uitlezen — IMPLEMENTED_TESTED
- [ ] F114 Alle zes kwaliteitsassen volledig met bewijs aftekenen — PARTIAL
  - Reden: Twee afzonderlijke lokale signed auditorprocessen meten alle zes vooraf vastgelegde assen voor twee uitsluitend vertrouwde Rust-reparatiefixtures; onafhankelijke externe veiligheidsaudit en gedragsequivalentie voor projectcode ontbreken.
- [x] F115 FTS5-p95-benchmark met 10.000 representatieve docs — IMPLEMENTED_TESTED
- [x] F116 Snelheidsbenchmark met minimaal vijf herhalingen — IMPLEMENTED_TESTED
- [x] F117 Betrouwbaarheid met tien identieke herhalingen — IMPLEMENTED_TESTED
- [x] F118 Geheugen- en CPU-pieken per proces meetbaar maken — IMPLEMENTED_TESTED
- [x] F119 Kosten, tokens en cloudverbruik per kandidaat loggen — IMPLEMENTED_TESTED
- [x] F120 Doorvoer, doorlooptijd en wachtlijndruk rapporteren — IMPLEMENTED_TESTED

## 13. Orchestratie, onafhankelijkheid en selectie

- [x] F121 Plan van 36 gespecialiseerde rollen implementeren — IMPLEMENTED_TESTED
- [x] F122 Adaptieve taakplanner met kritieke-pad-analyse — IMPLEMENTED_TESTED
- [x] F123 Onafhankelijke agents in geïsoleerde werkmappen starten — IMPLEMENTED_TESTED
- [x] F124 Taakafhankelijkheden als DAG afdwingen — IMPLEMENTED_TESTED
- [x] F125 Parallelle, begrensde projectscan uitvoeren — IMPLEMENTED_TESTED
- [x] F126 Actieve werkers dynamisch schalen op resourcegebruik — IMPLEMENTED_TESTED
- [ ] F127 Taken aan geschikte AI-modellen routeren — PARTIAL
  - Reden: v0.24 voegt naast de twee op standaardbibliotheekvragen getrainde modellen ook twee daadwerkelijk op echte CPython-compilerdiagnostiek getrainde codeherstelmodellen toe (Naive Bayes en perceptron). Op alle zeven minors zijn 120 trainingsgevallen, 32 afzonderlijke HMAC-ondertekende hold-outgevallen, kwaliteits- en CPU-latentiegates, negatieve beveiligingstests en maximaal één teken compile-only bewezen. Alleen dit beperkte syntaxdomein is afgedekt; voor willekeurige projectbugs ontbreekt nog geautoriseerde algemene AI-modeluitvoering en onafhankelijk extern bewijs; de 36-rollenroute blijft PLANNED_ONLY_NOT_EXECUTED.
- [x] F128 Zes-assige hard-gate voor mogelijke kandidaten — IMPLEMENTED_TESTED
- [x] F129 Objectief beste bewezen reparatie selecteren — IMPLEMENTED_TESTED
- [x] F130 Hoogstens één onafhankelijk geverifieerde reserve bewaren — IMPLEMENTED_TESTED

## 14. Gebruikersinterface en integratie

- [x] F131 JSON-uitvoer van bestaande CLI-commando's — IMPLEMENTED_TESTED
- [x] F132 Betekenisvolle CLI-exitcodes voor foutpaden — IMPLEMENTED_TESTED
- [x] F133 JSON-testmatrix en verifieerbaar lokaal testrapport — IMPLEMENTED_TESTED
- [ ] F134 GitHub Actions op externe runner uitvoeren en controleren — NOT_RUN
  - Reden: De CI-workflow staat in de bron, maar is niet op een externe GitHub-runner uitgevoerd.
- [ ] F135 IDE- en LSP-integratie voor VS Code/PyCharm — PARTIAL
  - Reden: De bestaande LSP-client en JetBrains-template zijn getest. R6 startte bovendien de echte VS Code 1.142.0-host: activatie, echte Python-LSP-initialisatie, ongeautoriseerde quickfixweigering en lokale edit-/stale-versionproeven PASS. PyCharm-host, volledige interactieve goedkeuringsflow en officiële multiplatform VSIX-distributie blijven NOT_RUN.
- [x] F136 Interactieve terminalinterface (TUI) — IMPLEMENTED_TESTED
- [x] F137 Webdashboard voor diagnose en reparaties — IMPLEMENTED_TESTED
- [x] F138 MCP- of plugininterface voor AI-omgevingen — IMPLEMENTED_TESTED
- [ ] F139 Git-branch, diffreview en PR-goedkeuring integreren — PARTIAL
  - Reden: v0.23 voert echte bare Git-remote, writer-/reviewerclones, featurebranch, SHA-gepinde diff, Ed25519-ondertekende eenmalige goedkeuring en merge/push met tamper- en replaynegatieven uit op alle zeven minors; een echte externe GitHub-/GitLab-PR, platform-revieweridentiteit en API-goedkeuring ontbreken.
- [x] F140 Notificaties, webhookevents en auditexport — IMPLEMENTED_TESTED

## 15. Distributie, levenscyclus en OS-support

- [x] F141 Linux x86_64 releasebinary bouwen — IMPLEMENTED_TESTED
- [x] F142 Geautomatiseerde Cargo-tests incl. Ruff-fixtures — IMPLEMENTED_TESTED
- [x] F143 Clippy met waarschuwingen als errors — IMPLEMENTED_TESTED
- [x] F144 Cargo.lock voor reproduceerbare dependencyselectie bewaren — IMPLEMENTED_TESTED
- [x] F145 Windows-build en runtimecompatibiliteit testen — IMPLEMENTED_TESTED
  - Bewijs: Native Windows 11 Home/Core build 26300 AMD64, offline releasebuild, 95 scoped Rust-/PE-testgevallen, 30 echte release-runtime-/compile-/referentieaanroepen en 6 opslag-/rollbackaanroepen. Zie `evidence/windows_r6/CORE_VALIDATION.json`. Dit tekent uitsluitend gecontroleerde lokale fixtures af; externe CI en volledige Windows-productcompatibiliteit blijven ongekwalificeerd.
- [ ] F146 macOS-build en runtimecompatibiliteit testen — NOT_RUN
  - Reden: OUT_OF_SCOPE_NOT_A_PASS: de gebruiker verlangt uitsluitend Windows 11 Home x64. Historische macOS-broninspectie wordt bewaard, maar telt niet als Windows- of volledige macOS-uitvoertest.
- [ ] F147 ARM64-binary en native extensies testen — NOT_RUN
  - Reden: OUT_OF_SCOPE_NOT_A_PASS voor ARM64: het gekozen doel is Windows x64 Intel/AMD. Geen echte ARM64-runner/artifact uitgevoerd; historische ARM64-tests zijn geen Windows-x64-productkwalificatie.
- [x] F148 Ondertekende en verifieerbare software-releases leveren — IMPLEMENTED_TESTED
- [x] F149 Atomaire software-update met automatische rollback — IMPLEMENTED_TESTED
- [ ] F150 Disaster recovery en productie-upgradeproces testen — PARTIAL
  - Reden: v0.26 voert nu echte geïsoleerde SQLite-WAL-recovery uit met childprocess-crash vóór/na commit, SHA-/logische herkomstcontrole, niet-overschrijvend herstel, lokaal getekende canaryrollback en werkelijk gemeten milliseconde-RTO/RPO. 161/161 regressies en 7/7 echte lokale herstelproeven zijn geslaagd op CPython 3.9–3.15.2. Productie- en offsite-herstel, onafhankelijke uitgeversidentiteit, andere OS'en en echte netwerk-/datacenteruitval zijn niet getest.

## 16. Debug Adapter Protocol en remote debugging

- [x] F151 DAP-handshake, versieonderhandeling en capabilities implementeren — IMPLEMENTED_TESTED
- [x] F152 DAP launch, attach en detach met expliciete sessiebevoegdheid — IMPLEMENTED_TESTED
- [x] F153 Debugsessies hervatten, herstarten en gecontroleerd afsluiten — IMPLEMENTED_TESTED
- [x] F154 DAP-functie-, exception- en data-breakpoints ondersteunen — IMPLEMENTED_TESTED
- [x] F155 Threads, processen en child-processen via DAP enumereren — IMPLEMENTED_TESTED
- [x] F156 DAP `stackTrace`, `scopes` en `variables` zonder datalekken leveren — IMPLEMENTED_TESTED
- [x] F157 DAP-`evaluate` en wijziging van variabelen apart autoriseren — IMPLEMENTED_TESTED
- [x] F158 DAP-events voor stop, continue, output en beëindiging leveren — IMPLEMENTED_TESTED
- [x] F159 Remote-debugverbinding versleutelen en wederzijds authenticeren — IMPLEMENTED_TESTED
- [x] F160 Bronpaden vertalen tussen host, container, WSL en remote omgeving — IMPLEMENTED_TESTED

## 17. Asyncio, threads, processen en gedistribueerde taken

- [x] F161 Niet-geawaitte coroutines en vergeten task-scheduling herkennen — IMPLEMENTED_TESTED
- [x] F162 Onopgehaalde asyncio-taskexceptions met oorspronkelijke oorzaak rapporteren — IMPLEMENTED_TESTED
- [x] F163 Async cancellation, timeouts en deadlocks per task diagnosticeren — IMPLEMENTED_TESTED
- [x] F164 `TaskGroup`, `ExceptionGroup` en `except*` correct ontleden — IMPLEMENTED_TESTED
- [x] F165 Trage event-loopcallbacks en blokkerende sync-functies detecteren — IMPLEMENTED_TESTED
- [x] F166 Threadlocks, racecondities en deadlockgrafen onderzoeken — IMPLEMENTED_TESTED
- [x] F167 `fork`, `spawn` en `forkserver` met versie- en OS-verschillen testen — IMPLEMENTED_TESTED
  - Bewijs: Windows x64 op zeven stabiele CPython-minors plus primair gepinde 3.16.0a1. Werkelijke spawn/IPC, twee beleidsroutes, fouten, timeouts, eigen proces-/kanaalopruiming en native unsupported-fork/forkserverorakels; expliciete previewtoestemming en exacte fase-/EXE-pin. Onafhankelijke bron-/bewijsreview PASS. Zie `evidence/windows_r8/F167/`; Linux-methoden worden op Windows niet als uitgevoerd voorgesteld. Volledige toekomstige stabiele 3.16 en productkwalificatie blijven apart open.
- [x] F168 Debugcontext en tracering gecontroleerd aan child-processen doorgeven — IMPLEMENTED_TESTED
- [x] F169 `concurrent.interpreters` en interpreter-isolatie vanaf 3.14 onderzoeken — IMPLEMENTED_TESTED
- [x] F170 Tracecontext tussen services, queues en achtergrondjobs correleren — IMPLEMENTED_TESTED

## 18. Alternatieve interpreters, free threading en native runtimes

- [x] F171 Free-threaded CPython vanaf 3.13 herkennen als aparte buildvariant — IMPLEMENTED_TESTED
- [x] F172 Threadveiligheid en GIL-gedrag van packages onder free threading testen — IMPLEMENTED_TESTED
- [x] F173 Native extensies op subinterpreter-compatibiliteit controleren — IMPLEMENTED_TESTED
- [x] F174 PyPy en andere implementaties expliciet scheiden van CPython-resultaten — IMPLEMENTED_TESTED
- [x] F175 Debug/release-ABI, `abi3`, wheel-tags en SOABI vergelijken — IMPLEMENTED_TESTED
- [x] F176 Windows-paden, driveletters, UNC en PowerShell-quoting controleren — IMPLEMENTED_TESTED
- [ ] F177 macOS ARM64/x86_64 en universal wheels afzonderlijk testen — PARTIAL
  - Reden: OUT_OF_SCOPE_NOT_A_PASS voor deze Windows-only release. Historisch v0.27-bewijs betreft SHA256-gepinde macOS universal2/Mach-O-structuren (44 tests per CPython3.9–3.15), niet macOS-uitvoering of Windows-compatibiliteit. Om de 260 ID's te behouden blijft dit item zichtbaar en niet afgevinkt.
- [x] F178 Linux glibc/musl, manylinux/musllinux en native libraries controleren — IMPLEMENTED_TESTED
- [x] F179 Embedded Python, Jupyter-kernels en notebook-cellen diagnosticeren — IMPLEMENTED_TESTED
- [x] F180 Versiespecifieke AST-, bytecode- en tracebackverschillen als regressies bewaren — IMPLEMENTED_TESTED

## 19. Lockfiles, pakketinstallatie en herkomstverificatie

- [x] F181 Standaard `pylock.toml` volgens PEP 751 lezen en valideren — IMPLEMENTED_TESTED
- [x] F182 `uv.lock`, Poetry- en PDM-lockfiles via adapters importeren — IMPLEMENTED_TESTED
- [x] F183 Dependency groups, extras en build-systemvereisten reconstrueren — IMPLEMENTED_TESTED
- [x] F184 PEP 508-markers voor platform, implementatie en extras volledig oplossen — IMPLEMENTED_TESTED
- [x] F185 PEP 610 `direct_url.json`, VCS- en editable-installatieherkomst controleren — IMPLEMENTED_TESTED
- [x] F186 `EXTERNALLY-MANAGED`-omgevingen respecteren zonder systeeminstallatie — IMPLEMENTED_TESTED
- [x] F187 Wheel-`RECORD`, hashes, bestandsintegriteit en installatiestatus vergelijken — IMPLEMENTED_TESTED
- [x] F188 PyPI Integrity API en PEP 740-attestaties cryptografisch verifiëren — IMPLEMENTED_TESTED
- [x] F189 Yanked, verwijderde, pre-release en onbetrouwbare distributies herkennen — IMPLEMENTED_TESTED
- [x] F190 Offline en reproduceerbare dependency-installatie op geverifieerde artefacten — IMPLEMENTED_TESTED

## 20. Testkwaliteit, oracle en reproduceerbaarheid

- [x] F191 Projecteigen testcommando's alleen via expliciete allowlist uitvoeren — IMPLEMENTED_TESTED
- [x] F192 `pytest`, `unittest`, `tox` en `nox` correct ontdekken en adapteren — IMPLEMENTED_TESTED
- [x] F193 Line- én branchcoverage en mutation-score per herstelverschil rapporteren — IMPLEMENTED_TESTED
- [x] F194 Generatieve propertytests met vastgelegde seeds en shrinking — IMPLEMENTED_TESTED
- [x] F195 Python-parser, Rust-CLI, update-ingestie en FTS-query's fuzztesten — IMPLEMENTED_TESTED
- [x] F196 Origineel en kandidaat differentieel vergelijken met identieke fixtures — IMPLEMENTED_TESTED
- [x] F197 Tijd, locale, random, filesysteem en omgevingsvariabelen reproduceerbaar maken — IMPLEMENTED_TESTED
- [x] F198 Flaky tests detecteren zonder onterechte PASS of stilzwijgend overslaan — IMPLEMENTED_TESTED
- [x] F199 Betrouwbare mediane, p95- en regressiedrempels met herhalingen meten — IMPLEMENTED_TESTED
- [x] F200 Foutinjectie bij database-, netwerk- en update-rollback uitvoeren — IMPLEMENTED_TESTED

## 21. Beveiliging, privacy en adversariële scenario's

- [x] F201 Versiegebonden threatmodel voor code, packages, AI en updatepad bijhouden — IMPLEMENTED_TESTED
- [x] F202 Malafide metadata, zipbommen en oversized documentatie onder quotum verwerken — IMPLEMENTED_TESTED
- [x] F203 Path traversal, symlink-TOCTOU en hardlink-aanvallen mitigeren — IMPLEMENTED_TESTED
- [ ] F204 Ongeschikte Python-code veilig isoleren met echte OS-/VM-grenzen — BLOCKED
  - Reden: Een echt WSL2-prototype is op vaste eigen afschermingsproeven getest. Onbekende projectcode is niet uitgevoerd; productintegratie, volledige ontsnappingscontrole en onafhankelijke veiligheidskwalificatie ontbreken.
- [ ] F205 Testbestandsysteem read-only maken behalve expliciete tijdelijke paden — BLOCKED
  - Reden: Het aangescherpte WSL2-prototype weigert daadwerkelijk writes buiten expliciete private tmpfs, ook op root/proc/dev; alleen de noodzakelijke devicehandelingen zijn toegestaan. Deze vaste probes zijn nog geen kwalificatie van het volledige projecttestbestandssysteem.
- [ ] F206 Netwerktoegang en DNS van onbekende testcode aantoonbaar blokkeren — BLOCKED
  - Reden: Het WSL2-prototype blokkeert vaste netwerk-, DNS- en syscallprobes werkelijk. Een volledig geïntegreerde onbekende-projectrunner en passende onafhankelijke veiligheidsaudit ontbreken.
- [ ] F207 Secrets, tokens, persoonsgegevens en broncodefragmenten uit logs redigeren — PARTIAL
  - Reden: v0.25 voegt een gesloten privacy-eventschema met SHA256/lengte, strikte type- en metadata-validatie en een koppeling aan de bestaande procesresultaatredactie toe; 182/182 Python-tests slagen op zeven minors. v0.26 vervangt daarnaast rechtstreeks in de echte Rust-CLI- en kennisfoutpaden het loggen van ruwe child-stderr door SHA256/lengte, met positieve en negatieve Rust-tests. Volledige verificatie van ELK updater-/trace-/metadatapad en onafhankelijke privacy-audit ontbreken nog.
- [ ] F208 Prompt-injection, onbetrouwbare documentatie en tool-output isoleren — PARTIAL
  - Reden: v0.27 implementeert data-only outputverificatie met HMAC-verzegelde trust-policy en bron, exacte SHA256/HTTPS-pins, anti-rollback op basis van aangeleverde vertrouwde vorige receipt en adversariële subprocessketen; 45 tests per CPython3.9–3.15 (315/315) slagen. Werkelijke externe AI-/toolconsumenten, externe adversariële audit en historie bij ontbrekend ontvangstbewijs zijn niet gekwalificeerd.
- [x] F209 SBOM, kwetsbaarheden en herkomst van binary's en dependencies auditen — IMPLEMENTED_TESTED
- [x] F210 Python-audithooks uitsluitend voor observatie gebruiken, niet als sandbox — IMPLEMENTED_TESTED

## 22. Kennisopbouw, retrieval en versiecontext

- [x] F211 Officiële PEP-wijzigingen, status en supersedes-relaties synchroniseren — IMPLEMENTED_TESTED
- [x] F212 Package-releasenotes en deprecationvensters per versie vastleggen — IMPLEMENTED_TESTED
- [x] F213 Documentatiesecties aan exacte Python-, package- en platformversies koppelen — IMPLEMENTED_TESTED
- [x] F214 Gedownloade codevoorbeelden apart compileren/testen per interpreter — IMPLEMENTED_TESTED
- [x] F215 `.pyi`-typestubs, signatures, overloads en API-renames indexeren — IMPLEMENTED_TESTED
- [x] F216 Hybride FTS/vector-retrieval met harde bron- en versiefilters — IMPLEMENTED_TESTED
- [x] F217 Tegenstrijdige of verouderde bronnen detecteren en laten herbeoordelen — IMPLEMENTED_TESTED
- [x] F218 Bronlicenties, citatielimieten en opnamebevoegdheden administreren — IMPLEMENTED_TESTED
- [x] F219 Incrementele deletions/tombstones, 304 en foute caches herstellen — IMPLEMENTED_TESTED
- [x] F220 Kennis- en testschema automatisch aanpassen aan nieuwe syntaxfeatures — IMPLEMENTED_TESTED

## 23. Databasebeheer, schaal en herstel

- [x] F221 SQLite WAL-schrijfconflicten en concurrente lezers stresstesten — IMPLEMENTED_TESTED
- [x] F222 FTS5-integritycheck, `rebuild` en `optimize` gecontroleerd uitvoeren — IMPLEMENTED_TESTED
- [x] F223 Transactionele schemamigraties met versienummer en rollback uitvoeren — IMPLEMENTED_TESTED
- [x] F224 Backup/restore inclusief WAL en SHA-verificatie periodiek beproeven — IMPLEMENTED_TESTED
- [x] F225 Vectorindex per Python- en packageversie gescheiden en gesynchroniseerd houden — IMPLEMENTED_TESTED
- [x] F226 Historische experimentdata in DuckDB betrouwbaar analyseren — IMPLEMENTED_TESTED
- [x] F227 Dependency- en API-provenancegrafen met bronlinks doorzoeken — IMPLEMENTED_TESTED
- [x] F228 Immutabele snapshots, retentie en archiveringsregels per experiment toepassen — IMPLEMENTED_TESTED
- [x] F229 Databases versleutelen en sleutels gecontroleerd roteren — IMPLEMENTED_TESTED
- [x] F230 Zoeklatentie en geheugengebruik bij miljoenen documentdelen benchmarken — IMPLEMENTED_TESTED
  - Bewijs: 1.050.000 genormaliseerd unieke originele tekstspans uit 106.947 pagina's / 72.244 domeinen van een primair SHA-gepinde FineWeb-Edu-shard. Vijf verse Windows-processen × 100 echte FTS5-queries: p95 33,76–34,45 ms; werkelijk piekgeheugen circa 113 MB en CPU-/HANDLE-metingen vastgelegd. Definitieve bron, provenance, read-only Windows-directory/leaf/SQLite-binding en alle 500 samples onafhankelijk beoordeeld; extra 100 queries via de echte R8-Rust-binary PASS. Zie `evidence/windows_r8/F230/`. Scope: generieke Engelstalige documentretrieval; geen koudcache-, ANN-, API-relevantie- of productreleaseclaim. Corpus blijft lokaal.

## 24. Adaptieve uitvoering, onafhankelijke audits en budgetten

- [x] F231 Taakqueue met prioriteit, backpressure en deadline-bewaking beheren — IMPLEMENTED_TESTED
- [x] F232 Kritieke-padverschillen en adaptieve werkeraantallen realtime berekenen — IMPLEMENTED_TESTED
- [x] F233 CPU, RAM, tokenkosten en tijd per kandidaat/agent verplicht meten — IMPLEMENTED_TESTED
- [x] F234 Afzonderlijke agentwerkruimtes en immutabele bron-snapshots afdwingen — IMPLEMENTED_TESTED
- [x] F235 Modelrouter op eerdere kwaliteit, latentie, kosten en toepasselijkheid testen — IMPLEMENTED_TESTED
- [x] F236 Reparatievarianten onafhankelijk initialiseren en correlatie meten — IMPLEMENTED_TESTED
- [x] F237 Zes vooraf vastgelegde PASS-drempels technisch vóór ranking afdwingen — IMPLEMENTED_TESTED
- [x] F238 False-positive-rate, regressie, doorvoer en herstelkwaliteit per release volgen — IMPLEMENTED_TESTED
- [ ] F239 Human approval voor risicovolle mutaties, installaties en releases verplichten — PARTIAL
  - Reden: R5 voegt verplichte Rust-predispatchcontrole toe met vaste installatiegebonden private Windows-sleutel, command-/binary-/doelhashes en duurzame eenmalige nonce. Getypeerde lokale catalogus-, backup- en canaryroutes worden werkelijk getest; onbekende muterende adapters en onbeperkte update-watch blijven fail-closed HOLD. Dit bewijst lokale HMAC-autorisatie, geen extern geauthenticeerde menselijke goedkeuring, onafhankelijke antirollbackhistorie of volledige installatie-/productiereleaseketen. Die vereisten blijven open.
- [x] F240 Beslislog met primaire kandidaat, maximaal één reserve of `NO_WINNER` auditen — IMPLEMENTED_TESTED

## 25. IDE-ervaring, distributie en productiebeheer

- [ ] F241 Automatische DAP-conformantietests voor VS Code- en PyCharm-clients — PARTIAL
  - Reden: Echte DAP-stdio- en Node/LSP-transportregressies blijven scoped bewijs. R6 testte ook de echte VS Code-LSP-host, maar niet volledige DAP-debugsessies in VS Code én PyCharm of externe Windows/macOS-builds.
- [x] F242 LSP-codeacties/quickfixes aan goedgekeurde hersteldiffs koppelen — IMPLEMENTED_TESTED
- [x] F243 TUI-toetsenbordbediening en toegankelijkheid testen — IMPLEMENTED_TESTED
- [x] F244 Websessies authenticeren, autoriseren en van audittrail voorzien — IMPLEMENTED_TESTED
- [x] F245 Python-package, Rust-binary en CLI-launchers gescheiden distribueren — IMPLEMENTED_TESTED
- [x] F246 Plugin- en updaterkanalen op publisheridentiteit en beleid afdwingen — IMPLEMENTED_TESTED
- [ ] F247 Reproduceerbare OCI-/containerimages met sandboxprofielen publiceren — PARTIAL
  - Reden: Een echte OCI-image-layoutkandidaat van de SHA256-gepinde, werkelijk opnieuw gebouwde Rust v0.25-ELF is tweemaal byte-identiek via Rust CLI en Python gegenereerd, met geverifieerde manifest/config/layer-digests, sandboxvereisten en 84/84 positieve en negatieve tests op CPython 3.9–3.15.2. De ELF is dynamisch gelinkt; OCI-runtime-uitvoering, afgedwongen sandboxprofiel, overige OS/architecturen en daadwerkelijke publicatie zijn NIET getest of geautoriseerd.
- [ ] F248 Windows, macOS, Linux en ARM-artifacts in externe CI uitvoeren — NOT_RUN
  - Reden: De v0.28-workflow voert na integratie Windows Server 2025 x64 × CPython3.9–3.15 en Rust native tests uit, met falende matrixcellen zichtbaar en minimale repositoryrechten. De workflow is nog NIET uitgevoerd. macOS/Linux/ARM-distributie is voor deze Windows 11 Home x64-release OUT_OF_SCOPE_NOT_A_PASS; de exacte Home-editie vereist afzonderlijk bewijs.
- [x] F249 Opt-in telemetrie, privacyredactie en anonimiseerbare supportbundels leveren — IMPLEMENTED_TESTED
- [x] F250 Canary rollout, healthcheck en automatisch herstel na mislukte release testen — IMPLEMENTED_TESTED

## 26. Ecosysteemspecifieke Python-projecten

- [x] F251 NumPy shape-, dtype-, broadcasting- en native ABI-fouten classificeren — IMPLEMENTED_TESTED
- [x] F252 Pandas-index-, dtypes- en dataframeschemafouten diagnosticeren — IMPLEMENTED_TESTED
- [x] F253 PyTorch CPU/CUDA-, devices- en checkpointversies onderscheiden — IMPLEMENTED_TESTED
  - Bewijs: `evidence/windows_v029/F253-runtime.json`, `F253-seven-minor.json` en `F253-independent-review.json`.
- [x] F254 TensorFlow/JAX-device-, graph- en compilemodusregels herkennen — IMPLEMENTED_TESTED
  - Bewijs: `evidence/windows_v029/F254-verdict.json` en `F254-independent-review.json`.
- [x] F255 Django/FastAPI/Flask-routes, dependency injection en middleware inspecteren — IMPLEMENTED_TESTED
- [x] F256 SQLAlchemy-/ORM-migraties en async/sync-databasefouten opsporen — IMPLEMENTED_TESTED
- [x] F257 Celery-, Redis- en queueworkerfouten over procesgrenzen correleren — IMPLEMENTED_TESTED
- [x] F258 Arrow/Parquet/protobuf- en serialisatiecompatibiliteit analyseren — IMPLEMENTED_TESTED
- [x] F259 Cython, cffi en PyO3-native extensiefouten en crashes classificeren — IMPLEMENTED_TESTED
- [x] F260 Versiegebonden packageadapter-SDK met eigen verificatiebewijzen aanbieden — IMPLEMENTED_TESTED

## Codefunctie-register: geen vergeten implementaties

De productfuncties hierboven zijn *eisen*; daarnaast staan **alle werkelijk
gedefinieerde Rust- en Python-functies**, inclusief helpers en tests,
én de 25 bestaande Rust-CLI-(sub)commando's in
`config/code_symbol_inventory.json`. Het bijbehorende commando:

```bash
python3 tools/audit_function_checklist.py --check
```

Dit faalt wanneer een functienaam toegevoegd, hernoemd of verwijderd wordt
zonder het overzicht expliciet bij te werken. Voor handmatige inspectie:

```bash
python3 tools/audit_function_checklist.py --dump-symbols
```

**Belangrijk:** 260 eisen is een zorgvuldig geïnventariseerde *huidige
baseline*, geen wiskundig complete verzameling van alle toekomstige Python-
API's. Elke nieuwe Python-release, PEP, dependency-, beveiligings- of
gebruikersbehoefte krijgt nieuwe F-ID's vóór implementatie. Niet op eigen
houtje bestaande regels of `NOT_RUN` naar PASS veranderen.

### Bronnen voor het aanvullen van deze lijst

- [Python `pdb`-documentatie](https://docs.python.org/3/library/pdb.html):
  runtime-debugging, breakpoints, stackframes en post-mortem.
- [Python `sys.monitoring`](https://docs.python.org/3/library/sys.monitoring.html):
  runtime-events vanaf Python 3.12; oudere versies hebben een andere backend.
- [PyPA dependency-specifiers](https://packaging.python.org/en/latest/specifications/dependency-specifiers/)
  en [Core Metadata](https://packaging.python.org/en/latest/specifications/core-metadata/):
  markers, extras en `Requires-Python`.
- [PyPI JSON API](https://docs.pypi.org/api/json/) en
  [Index API](https://docs.pypi.org/api/index-api/): package- en releasegegevens.
- [Python-debugging/profiling-overzicht](https://docs.python.org/3/library/debug.html):
  debugging, tracing en profiling als afzonderlijke categorieën.
- [Debug Adapter Protocol](https://microsoft.github.io/debug-adapter-protocol/overview.html):
  IDE-aansturing, stackframes, threads, scopes en variabelen.
- [PEP 751 / `pylock.toml`](https://packaging.python.org/en/latest/specifications/pylock-toml/)
  en [Direct URL Origin](https://packaging.python.org/en/latest/specifications/direct-url/):
  lockfiles, herkomst en herhaalbare installaties.
- [PyPI package-provenance](https://docs.pypi.org/using-pypi/package-security/provenance/)
  en [Integrity API](https://docs.pypi.org/api/integrity/): ondertekende attestaties.
- [Asyncio-ontwikkelrichtlijnen](https://docs.python.org/3/library/asyncio-dev.html),
  [multiprocessing](https://docs.python.org/3/library/multiprocessing.html),
  [free-threaded Python](https://docs.python.org/3/howto/free-threading-python.html)
  en [meerdere interpreters](https://docs.python.org/3/library/concurrent.interpreters.html).
- [Python audit-hooks](https://docs.python.org/3/library/sys.html):
  geschikt voor observatie, niet als security-sandbox.
- [SQLite FTS5](https://sqlite.org/fts5.html) en
  [OpenTelemetry](https://opentelemetry.io/docs/specs/otel/): indexintegriteit
  en observability bij grotere workloads.
