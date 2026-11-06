# Actuele Windows-werkstand R5 — 2026-11-06

**232/260 ontwikkelfuncties op afgebakende fixtures getest; 28 open.**
F253 (PyTorch CPU/CUDA/checkpointformaten) en F254 (TensorFlow/JAX
CPU, graph/XLA/JIT en geautoriseerde WSL-GPU) zijn werkelijk geïmplementeerd,
getest en afzonderlijk beoordeeld. Zie `docs/FUNCTION_CHECKLIST.md` en
`evidence/windows_v029/` voor exacte versies, hashes en subresultaten.

R5 herstelt Windows-sleutel- en ACL-controles, descriptorgebonden bronlezers,
projectscans, DAP/LSP-pipes, padmapping, private checkerbundels en echte
PowerShell 7.5.13-parserproeven. De gerichte zevenversiematrices bevatten
3.339 geslaagde testuitvoeringen zonder skips. De Rust-dispatcher verplicht
lokale, installatiegebonden HMAC-goedkeuring voor getypeerde mutaties; echte
back-up-, verificatie- en canary-terugrolproeven slagen met eenmalige tokens.
Dit is lokale autorisatie, geen onafhankelijk geauthenticeerde menselijke
goedkeuring. Ongetypeerde mutaties en onbeperkte update-watch blijven HOLD.

De brede Python 3.14.10-run blijft FAIL: 2.195 tests, 26 assertion failures,
26 errors en 99 skips. In rechtstreeks vergelijkbare geregistreerde rijen
zijn 107 eerdere FAIL nu PASS. Niet uitgevoerde Linux-gates worden op
Windows niet als PASS geteld; de platformconstraints zijn apart in echte
WSL uitgevoerd. Zie STATUS.json in het bewijs-ZIP voor hashes en scope.
Sandbox, uitgeverspins, externe audit en overige open gates blijven apart.
Dit is geen productrelease.
Hieronder staat de historische v0.27-ontwikkelbeschrijving.

# Rust Python Healer — ontwikkelversie v0.27

> **Windows-only v0.28-ontwikkelkandidaat:** deze bronboom bevat de volledige
> v0.27-code plus `windows_qa/` en `.github/workflows/windows-native-matrix.yml`.
> De Windows 11 Home x64/NVIDIA-doelconfiguratie is vastgelegd, een echte
> zevenversies-Windows-CI (inclusief 100 geselecteerde taaltests per minor)
> is voorbereid, en de Linux ELF-updater weigert updates op Windows expliciet.
> **Dit is geen geteste Windows-release:** echte Windows- en GPU-runs, de
> Windows-PE-updater, platformisolatie en productiekwalificatie blijven open.
> Zie `docs/WINDOWS_ONLY_v028.md` voor nieuw lokaal bewijs en beperkingen.

Een **conservatieve Rust-CLI** voor het onderzoeken van Python-code, het
automatisch genereren van herstelkandidaten en het opbouwen van een lokale,
**versiegebonden kenniscatalogus**. De kern is Rust, niet een herschreven
Python-interpreter. Python blijft de bron van waarheid voor zijn eigen syntax
en bytecodecompilatie.

> **Status v0.23 (historische, bevroren baseline):** werkende maar nog beperkte Rust-debugger met lokale
> herstelkandidaten, versiegebonden Python-kennis en gecontroleerde
> integratieadapters. **13.818/13.818 Python-unittests** zijn op echte
> CPython-versies 3.9–3.15 geslaagd, evenals **700/700 taalchecks** en
> **69/69 Rust-tests** en **378/378 offline Rust/Python-adapterchecks**.
> De checklist heeft **230/260** functies op een
> afgebakende fixturebasis getest. Dit is **geen** volledig autonome,
> productiegekwalificeerde hersteller voor willekeurige Python-projecten:
> uitvoerisolatie en algemene projectregressie blijven uitdrukkelijk open.

## v0.27 — acht extra werkelijk uitgewerkte open checklistpunten

De **260 oorspronkelijke functie-ID's blijven ongewijzigd**. De nu geteste
deelimplementaties worden niet met een volledige functie- of release-PASS
verward. In het bijzonder blijft de ontbrekende externe platform-/veiligheids-
of praktijkevidentie een harde blokkade.

- **F090:** lokaal/offline, expliciet geautoriseerde Ed25519 Rust-binary-
  update met OpenSSL-/artifact-/manifest-pins, lock, versie-CAS en rollback;
  **231/231** Python-regressietests. Geen productiereleasebevoegdheid.
- **F135/F241:** concrete VS Code/Node LSP-client en JetBrains LSP4IJ-
  starter, plus echte Python-stdio-protocoltests; Node-tests zijn op alle
  zeven echte CPython-versies uitgevoerd. Native IDE-hosts niet gestart.
- **F167:** fail-closed `fork`/`spawn`/`forkserver`-keuze en uitdrukkelijk
  geautoriseerde, apart geverifieerde `spawn`-fallback; **twee configuratie-
  kandidaten met gepinde sourcehash** zijn driemaal per Python-versie
  gemeten. Drie van zes kwaliteitspoorten blijven NOT_RUN en er is **geen
  gekwalificeerde winnaar**. Forkserver/Unix-socket nog geblokkeerd.
- **F177:** een echt SHA256-gepind officieel PyPI `universal2`-wheel en
  x86_64/ARM64 Mach-O-slices structureel gecontroleerd; **308/308**
  negatieve/positieve tests. Geen macOS-hostuitvoering.
- **F208:** HMAC-verzegelde bron-/policychecks, pin- en versiebewijs,
  adversariële tool-output als data met onafhankelijke subprocessketen;
  **315/315** tests. Geen externe AI-/tool-runtime of redteam-audit.
- **F253/F254:** begrensde, niet-uitvoerende PyTorch-checkpointinspectie
  en TensorFlow/JAX graph-/device-/JIT-AST-analyse; **406/406** Python-
  regressies. Echte frameworkinstallaties/GPU-checks blijven NOT_RUN.

De **negen nieuwe v0.27-regressiesuites bevatten samen 221 testgevallen per
interpreter, 1547/1547 geslaagd** op de zeven daadwerkelijk gestarte
CPython-versies 3.9–3.15.2; de in een Python-suite opgenomen Node-clienttests
zijn hierin indirect opgenomen. De echte Rust v0.27.0-release is opnieuw
gebouwd en heeft **71/71** Rust-tests doorstaan. De oorspronkelijke
**700/700** Python-taalregressies slagen, zonder claim van volledige
ecosysteem- of productiekwalificatie.

Een aanvullende ZIP-importtest ontdekte en repareerde een Python3.9-specifieke
fout die door gewone bronboomtests verborgen was gebleven: een lege
`__package__` in de legacy wheel-loader. Twee falende wheel-kandidaten zijn
afgewezen; de herbouwde offline wheel onder `dist/offline-v0.27-release/`
importeert zes relevante modules nu op zeven echte CPython-versies en is
tweemaal byte-identiek gebouwd. De variantregistratie met de negatieve
bewijzen staat in `evidence/RELEASE_WHEEL_VARIANTS_v0.27.json`.

Checklist: **230/260 `IMPLEMENTED_TESTED`, 16 `PARTIAL`, 7 `NOT_RUN`,
7 `BLOCKED`, 0 `NOT_IMPLEMENTED`**. Alle dertig resterende punten hebben
een afzonderlijke, toetsbare reden onder
[`docs/FUNCTION_CHECKLIST.md`](docs/FUNCTION_CHECKLIST.md).
De zes kwaliteitspoorten en 3× herhaalde kandidaatmetingen staan in
`evidence/PROCESS_POLICY_BENCHMARK_v0.27-release.json`; het volledige overzicht
staat in `evidence/VALIDATION_v0.27.md`.

## v0.26 — echt geteste herstel- en beveiligingsuitbreidingen

- **F150 lokale herstelproeven:** echte geïsoleerde SQLite-WAL-procescrashes
  voor/na een commit, herkomst-/SHA-integriteit, foutinjectie, gemeten
  RTO en RPO, niet-overschrijvend herstel en ondertekende canaryrollback.
  **161/161** nieuwe Python-tests en **7/7** echte lokale herstelproeven.
  Productieherstel/offsite-verlies is niet gekwalificeerd.
- **F239 mutatiegoedkeuring:** een aparte éénmalig getekende scopesleutel
  beperkt de echte canarymutatie tot exacte bestandshashes, actie, actor en
  nonce, naast de al bestaande getekende operatorintentie. **161/161** tests.
  Nog geen verplichte handhaving in alle Rust-mutatiecommando's.
- **F241 DAP-client:** een eigen onafhankelijke lokale DAP-testclient
  controleert echte frames, breakpoints, variabelen, gebeurtenisvolgorde,
  HMAC-autorisatie en malformeerde frames. **140/140** tests; geen
  echte VS Code-/PyCharm-clientconformiteit geclaimd.
- **F207 Rust-logprivacy:** subprocess-stderr gaat in de echte Rust-
  diagnosefoutpaden nu uitsluitend als SHA256/lengte naar het foutbericht,
  met twee nieuwe negatieve/positieve Rust-tests. Onafhankelijke
  inspectie van alle applicatielogpaden ontbreekt nog.
- **Controle van alle open punten:** een nieuwe versiegebonden matrix
  registreert elk van de 30 open checklistpunten op elk van zeven
  CPython-minors. Van 210 feature-versiecellen tonen 56 uitsluitend
  **afgebakend testbewijs** en 154 `NOT_RUN`; nul voltooiverklaringen.

De vier nieuwe Python-regressiesuites (inclusief checklistmatrix)
slaagden samen **518/518**. De echt herbouwde Rust v0.26.0-release heeft
**71/71** Rust-tests doorstaan. De nieuwste CPython **3.15.2** beschikt
nu na een gecontroleerde libffi-herbouw ook over `_ctypes`, naast SQLite
FTS5; alle **45/45** actuele framework-/ORM-tests zijn daarop geslaagd.
Zie `evidence/VALIDATION_v0.26.md` voor grenzen en afwijkingen.

De checklist blijft eerlijk: **230/260 `IMPLEMENTED_TESTED`**,
**15 PARTIAL, 7 NOT_RUN, 7 BLOCKED en 1 NOT_IMPLEMENTED**.

## v0.25 — daadwerkelijk verbeterde, nog open checklistpunten

De 30 onafgewerkte F-items zijn **niet** stilzwijgend afgevinkt. Vier
hiervan hebben nieuwe, echte, afgebakend geteste implementaties gekregen:

- **F050:** SHA256-gepinde automatische CPython-microversietests op zeven
  exacte patches (700/700); de afzonderlijk geëiste 3.15.1 is eerlijk
  `NOT_RUN`, dus geen claim van complete microversiedekking.
- **F135:** robuustere LSP-stdio-headers en echte `didChange`-documentversies,
  inclusief weigering van stale quickfixes. Externe VS Code/PyCharm-
  clienttests ontbreken.
- **F207:** gesloten, begrensde logevent-redactie met werkelijke koppeling
  aan procesresultaatlogs; niet alle Rust-/Python-logpaden zijn beschermd.
- **F247:** een reproduceerbare OCI-image-layoutkandidaat met twee
  identieke SHA256-outputs en gecontroleerde blobintegriteit.
  Een echte container-/sandboxrun en imagepublicatie zijn **niet** gedaan.

De vier nieuwe suites hebben samen **504/504 tests** op zeven echte
CPython-minors; bovendien zijn **112/112 bestaande LSP-tests** herhaald.
De native Rust-release **0.25.0** is werkelijk gebouwd en zijn
**69/69 Rust-regressies** uitgevoerd; de offline wheel en ELF-archief staan
in `dist/offline-v0.25`. Dit is geen ondertekende productie-release.
De Rust↔Python-offlineadaptermatrix telt nu **399/399** gerichte controles
(57 per minor). Daarvoor is op de 3.15-minor de bestaande 3.15.0-runtime
gebruikt, omdat de nieuwe lokaal gebouwde 3.15.2 nog `_ctypes` mist voor
een libc-adapter; de overige v0.25-tests zijn wel op 3.15.2 uitgevoerd.
Checkliststatus: **230/260 bewezen**, nog
**13 PARTIAL, 7 NOT_RUN, 7 BLOCKED en 3 NOT_IMPLEMENTED**.
Alle exacte testgrenzen staan in `evidence/VALIDATION_v0.25.md`.

## v0.24 — twee echte codeherstelmodellen, zevenversies-metingen

- De Rust-CLI biedt nu `lab code-model-router`. In een begrensd
  **compile-only** domein worden een multinomiale naïeve Bayes en een
  multiclass perceptron daadwerkelijk getraind op telkens 120 door de
  lokale CPython-compiler afgekeurde syntaxvoorbeelden.
- Elk model wordt apart getoetst aan 32 niet in de training gebruikte,
  cryptografisch aan een auditor-sleutel gebonden gevallen. Voor
  Python **3.9 t/m 3.15** zijn samen **1.680 echte trainingsvoorbeelden**,
  **448 hold-outmodelproeven**, kwaliteitsdrempels, CPU-latentie en
  negatieve handtekening-/tamperproeven gemeten. Een kandidaat bevat
  uitsluitend een ééntekenwijziging en een SHA256, zonder broncode
  automatisch uit te voeren of te overschrijven.
- De werkelijke Rust↔Python-adaptermatrix is uitgebreid tot **392/392**
  controles. Ook **69/69** Rust-tests, inclusief de twee expliciet
  ingeschakelde Ruff-tests, zijn geslaagd. Een lokaal ondertekende
  selftest is **geen externe modelgoedkeuring**.
- De versiegebonden Rust-CLI-taalmatrix is opnieuw uitgevoerd op zeven
  **echte** interpreters: **100/100 geselecteerde syntax-/compilechecks
  per minor, samen 700/700**. Dit bewijst geen volledige pakketcompatibiliteit.
- De 3.15-minor gebruikt voor de taal- en modelmatrix ook de officieel
  gepubliceerde **CPython 3.15.2**-broncode, lokaal opnieuw gebouwd met
  echte SQLite-FTS5-ondersteuning. Daarop zijn nog 190 gerichte tests
  geslaagd; 14 Pandas-tests bleven overgeslagen vanwege ontbrekende
  `_ctypes`-builddependencies. Zie het nauwkeurige bewijsrapport.
- De checklistaudit telt nog steeds **230/260** begrensd bewezen functies.
  **F127 blijft PARTIAL:** dit leert vier syntaxklassen, niet alle
  mogelijke Python-bugs of alle AI-/LLM-modellen. De originele v0.23
  supply-chainsnapshot wordt apart met de bevroren v0.23-binary en
  `Cargo.lock` geverifieerd; de v0.24-release erft die kwalificatie niet.

Uitvoering met een expliciet aanwezige Python-interpreter:

```bash
target/release/rust-python-healer lab code-model-router --python python3.12 -- --mode selftest
python3.12 tools/audit_function_checklist.py --check
```

Voor de zeven afzonderlijke meetrapporten: `evidence/REAL_CODE_MODEL_MATRIX_v0.24.json`,
`evidence/LANGUAGE_MATRIX_v0.24.json`, `evidence/OFFLINE_LAB_MATRIX_v0.24.json` en
`docs/FUNCTION_CHECKLIST.md`.

## v0.23 — extra echte platform-, kennis-, debugger- en herstelproeven

Deze release bouwt voort op de v0.22-basis van **200/260** afgevinkte,
begrensd geteste functies. De nieuwe centrale checklist telt **precies
230/260 `IMPLEMENTED_TESTED`** en **30 met redenen gedocumenteerde open
punten**, gecontroleerd door de actuele bronsymbool-audit. Deze telling zegt
uitdrukkelijk niet dat willekeurige projecten of toekomstige releases volledig
zijn gekwalificeerd; zie `docs/FUNCTION_CHECKLIST.md` en
`evidence/VALIDATION_v0.23.md` voor de exacte testgrenzen.

- **Actual Python runtimes:** reguliere CPython 3.9–3.15, echte
  free-threaded CPython 3.13t–3.15t, echte PyPy 3.9–3.12 en aparte
  3.15-alpha/bèta/RC- plus 3.16-alphaobservaties. Een preview slaagt
  voor geselecteerde 100+8 taal-/syntaxcases, niet voor totale
  toekomstige productiecompatibiliteit.
- **DAP remote:** echte loopback-TLS 1.2+ met wederzijdse
  certificaatcontrole, gepinde leaf-SHA256, HMAC-framing en negatieven;
  gecontroleerde bronpadvertaling voor host, container, WSL en remote.
  Externe VS Code-/PyCharm-conformiteit ontbreekt.
- **Native en types:** echte C-extensie-/wheelcompilatie, subinterpreters,
  een GIL-uitgeschakelde threadstressfixture en PyPy-/ABI-scheiding.
  Echte `mypy` en `Pyright` gebruiken gecontroleerde typeconfiguraties
  voor zeven minors. Dat kwalificeert geen willekeurige projectplugins.
- **Kennis:** 747 officiële PEP's live via HTTPS in een doorzoekbare
  content-addressed FTS5-index, ETag/304-controle en echte DuckDB
  native SQL op alle zeven CPython-minors met compatibele versies.
  Nieuwe Python-syntaxfeatures sturen conservatieve, transactionele
  schemamigraties aan; een miljoen representatieve documenten ontbreekt.
- **Binaire update:** een werkelijk gebouwde Rust-release krijgt
  lokaal operator-toestemming via Ed25519 en een onafhankelijke
  SHA256-allowlist, draait een echte `--version`-canary, gebruikt een
  atomaire symlink-pointer en wordt bij falen naar de oude versie
  teruggezet. Geen automatische officiële publisher-/productie-update.
- **Ecosysteem:** echte versiegebonden NumPy-, Pandas-, Django-, FastAPI-,
  Flask-, SQLAlchemy-, Arrow-/Parquet-/protobuf-, Cython-/cffi-/orjson-
  fixtures op alle zeven minors; echte, geïsoleerde Redis/Celery met twee
  workers en crossprocess Redis Streams. PyTorch/TensorFlow/JAX en GPU's
  blijven zonder echte runtime-/hardwareproef `PARTIAL`.
- **Supply chain:** voor een echte lokale SBOM zijn 67 Cargo-crates en 33
  PyPI-distributies apart bij de officiële OSV-querybatch gecontroleerd;
  de exacte antwoord- en Rust-ELF-SHA256 zijn lokaal gepind. Een lege
  advisorylijst bewijst geen afwezigheid van kwetsbaarheden. De herkomst
  van individuele dependency-uitgevers blijft expliciet `UNKNOWN`.
- **Modelrouter:** twee werkelijk getrainde modellen (LSA en naïeve Bayes)
  zijn op dezelfde echte stdlib-docstrings geëvalueerd met onafhankelijke
  labels, gemeten kwaliteit, CPU-kosten, latentie en beveiligde feedback.
  **F235** is alleen in dat beperkte vraagdomein afgevinkt; algemene
  AI-bugrepairtaakroutering **F127** blijft `PARTIAL`.

De vooraf vastgelegde zes kwaliteitsassen, sandboxgrenzen en
onafhankelijke herhalingsoracles blijven verplicht. In een lokale fixture
`PASS` krijgen is géén bevestiging dat alle bestaande of toekomstige
Python-libraries en willekeurige projecten volledig worden begrepen.
Zie ook `docs/RUNTIME_AND_DATA_BOUNDARIES_v0.23.md`.

Voorbeelden van begrensde nieuwe adapters:

```bash
cargo run -- lab remote-dap --python python3.12 -- --fixture-pathmap-selftest
cargo run -- lab platform-matrix --python python3.12 -- --mode runtime
cargo run -- lab provenance --python python3.12 -- --mode capabilities
cargo run -- lab knowledge-scale --python python3.12 -- --mode capabilities
cargo run -- lab typecheck-integration --python python3.12 -- --mode capabilities
cargo run -- lab real-queue --python python3.12 -- --mode capabilities
cargo run -- lab real-model-router --python python3.12
# Bestaande SHA256-gepinde 100/100 OSV-snapshot: afzonderlijke auditor;
# vereist optioneel vooraf geïnstalleerde verifier-omgeving en privé-evidence.
python3 python/full_sbom_osv_v23.py --mode verify --project . \
  --tool-root .v23-pypi-verify --evidence .v23-official-evidence
```

## v0.22 — historische stand: exact 200 van 260 gecontroleerde functies

Deze release voegt **precies 25 extra** begrensd uitgevoerde functies toe:
de canonieke checklist telt nu **200 `IMPLEMENTED_TESTED`**, **28 `PARTIAL`**,
**18 `NOT_IMPLEMENTED`**, **7 `NOT_RUN`** en **7 `BLOCKED`**. Nog **60 open**.
De source-audit registreert 2.686 echte Rust-/Python-symbolen uit 157
bestanden en blokkeert ontbrekende redenen of ongeregistreerde wijzigingen.
Op de zeven echte CPython-versies **3.9 t/m 3.15** slaagden
**10.101/10.101 Python-unittests**, **700/700 taalchecks**,
**238/238 offline Rust/Python-integratiechecks**, **35/35 onafhankelijke
echte FTS5-documentdatabasemetingen** en **58/58 Rust-tests**. De 35
database-rondes meten 3.360 werkelijke queries met p95 onder 50 ms.

| Onderdeel | v0.22-uitbreiding | Wat niet is aangetoond |
|---|---|---|
| Runtime DAP | Echte `Content-Length`-frames, aparte HMAC-autorisaties, lifecycle, breakpoints, stack/scopes/variabelen en events van een harde vertrouwde fixture | Launch/attach van willekeurige programma's of echte VS Code-/PyCharm-conformiteit |
| Packagebeheer | Gecontroleerde lokale import- en lockgraph, PEP 751/610/668, uv-/Poetry-/PDM-adapters | Alle mogelijke lockschemas, externe VCS-uitgeversidentiteit of systeeminstallaties |
| Kwetsbaarheden | Werkelijke lokaal geïnstalleerde packageversies vergelijken met een ondertekende, versiegebonden lokale advisoryfeed | Actuele volledige officiële OSV-/CVE-ontvangst, publisherattestatie |
| Statische analyse | Intermodule statische callgraph en control flow, concrete alias- en mutatieflow | Universele Python-type-inferentie, dynamisch bewezen control flow/aliasing |
| Beveiliging | Descriptorgebonden symlink-/hardlink-/traversalweigering, versiebewust dreigingsregister en échte audit-hookobservatie | Bewezen OS-/VM-sandbox, alle platformen, externe veiligheidsaudit |
| Updater | Lokale HTTP/ETag-watchcycli, compile-only SHA-gepinde voorbeeldcode, migratie van oude slechte SHA's/ETags en tombstones | Officiële live bronnen en automatisch bijwerken van de Rust-binary |
| Database | Echte OpenSSL AES-256-GCM SQLite-back-ups, geauthenticeerd herstel en atomaire sleutelrotatie | Universele SQLCipher-ondersteuning en forensisch wissen van historische blokken |
| Platformlimieten | Linux `RLIMIT`-afgedwongen vertrouwde subprocessen, glibc/ELF-/wheel-policychecks | Native Windows, macOS of musl-executie, onbekende code isoleren |

De 36 specialistische **rollen** blijven een routeer-/planningsschema;
deze versie wordt niet voorgesteld als 36 actieve autonome AI-modellen.
Twee afzonderlijke lokale controleprocessen uit v0.21 blijven
zonder externe auditidentiteit of productie-releasebevoegdheid.
De resultaten per echte CPython 3.9–3.15 staan in
`evidence/VALIDATION_v0.22.md`.

Voorbeelden van de nieuwe offline adapters:

```bash
cargo run -- lab dap-runtime --python python3.12 -- --selftest
cargo run -- lab package-policy --python python3.12 -- --mode capabilities
cargo run -- lab encrypted-catalog --python python3.12 -- --mode trusted-selftest
cargo run -- lab security-controls --python python3.12 -- --mode audit
cargo run -- lab platform-constraints --python python3.12 -- --mode linux
```

Het bewijsregime blijft **NO EVIDENCE = NO PASS**: een vinkje bevestigt
de expliciet gecontroleerde lokale implementatie, **niet** een volledig
onafhankelijk gecertificeerd product, een veilige onbekende-code-runner of
automatische ondersteuning van toekomstige Python-versies.

## v0.21 — historische tussenstand: 175 van 260

De checklist telde destijds **175 `IMPLEMENTED_TESTED`**, **42 `PARTIAL`**,
**29 `NOT_IMPLEMENTED`**, **7 `NOT_RUN`** en **7 `BLOCKED`**: nog **85
open**. In v0.21 kregen precies 50 aanvullende F-ID's een vinkje, elk
uitsluitend binnen de in het bewijs omschreven lokale testgrenzen. Het
register bestrijkt 2.259 werkelijke broncodesymbolen in 141 bestanden.
De telling wordt automatisch geblokkeerd bij ontbrekende onderbouwing.
De zeven echte CPython-versies leverden **8.344/8.344 Python-unittests**,
**700/700 taalchecks**, **182/182 offline Rust-adapterchecks** en
**35/35 onafhankelijke FTS5-indexmetingen op echte stdlibdocumentatie**;
de Rust-suite telt **58/58 PASS**.

Nieuw in deze release:

- **Betrouwbare runtime-inspectie van uitsluitend ingebouwde fixtures:**
  breakpoints, stappen, scalar-watch, `bdb`, exceptions, threads, async en
  `sys.monitoring` waar de CPython-versie dat ondersteunt.
- **Structureel herstel en vergelijking:** tokens/comments behouden bij
  beperkte wijzigingen; twee onafhankelijke herstelstrategieën, echte
  gedragsequivalentietests en line/branch/mutation-gates.
- **Projectmetadata en packageverificatie:** geselecteerde PEP 440/508/735
  standaarden, twee afzonderlijke offline-pip-installaties, RECORD-controle,
  statische notebook-, runner- en stub-inspectie.
- **Kennis/DB-prestaties:** minimaal 10.000 unieke echte stdlib-documentatie-
  fragmenten per versie, met vijf afzonderlijk gestarte SQLite FTS5-metingen;
  geen synthetische documenten in deze prestatieclaim.
- **Integraties:** minimale MCP/LSP-protocollen, een lokale webinterface,
  cryptografisch afgeschermde sessies en getekende loopback-webhooks.
- **Begrensde automatisering:** twee echt afzonderlijke lokale controleprocessen,
  zes fail-closed kwalificatieassen, beperkt adaptieve workerverdeling en
  een ondertekende lokale canary-update met rollback.

**Geen algemene vrijgave:** deze resultaten bewijzen geen veilig uitvoeren of
automatisch repareren van willekeurige gebruikerscode. Een extern onafhankelijk
geauditeerde OS-sandbox, publieke uitgeversidentiteit, productie-updater,
externe audit en toekomstige CPython-versies zijn niet bewezen en blijven
open of gedeeltelijk. Zie `evidence/VALIDATION_v0.21.md`.

Nieuwe CLI-probes gebruiken `lab <adapter> --python <interpreter> -- ...`,
bijvoorbeeld `lab trusted-debugger`, `lab real-docs-benchmark`,
`lab ecosystem-diagnostics`, `lab knowledge-expansion`,
`lab distribution-probe` en `lab release-canary`.

## v0.20 — eerdere functies met controleerbare grenzen

De uitbreidingen voor v0.20 gebruiken de echte CPython-interpreters 3.9–3.15
en uitsluitend vertrouwde, lokale fixtures. De **actuele telling** en het
bewijs staan in `docs/FUNCTION_CHECKLIST.md` en `evidence/VALIDATION_v0.20.md`.

| Onderdeel | Concrete uitbreiding | Expliciete beperking |
|---|---|---|
| Dependencies | `lab transitive-resolver` met lokale backtracking en gecontroleerde conflictbewijzen | Alleen begrensde PEP-440-final-releases, geen installatie of volledige PEP 508 |
| Kennis | Statische stdlib-API-extractie, geverifieerde lokale package-signatures, API-deprecations en PEP-snapshots | Native/dynamische API's en officiële realtime synchronisatie niet compleet |
| Retrieval | `lab vector` voor exacte cosinus, FTS5/BM25-hybride retrieval en harde bron-, SHA- en versiegrenzen | Geen ingebouwd embeddingmodel, ANN of miljoen-documentproductiebewijs |
| Dataherstel | `lab backup-drill` migreert een opgegeven catalogus, plant lokale WAL/SHA-back-ups, herstelt en verifieert alle snapshots | Geen permanente OS-scheduler of geografisch gescheiden offsite-opslag |
| Statische veiligheid | Conservatieve codekwaliteit, quota-afgeschermde ZIP-controle en apart gehashte agentwerkruimtes | Geen OS-bewezen sandbox tegen onbekende code |
| Async/concurrentie | Runtime-metingen voor tasks/locks/traces, statische vergeten-awaitcheck en reproduceerbare threaded-racefixture | Alleen expliciet geïnstrumenteerde workloads; geen universele race- of deadlockdetector |
| Meting | Werkelijke Rust/Ruff/CPython-herhalingen, reproduceerbare fixtures en gecontroleerde betrouwbaarheidsscores | Geen bewezen correctheid voor willekeurige projecttests |
| Privacysupport | Opt-in redactie en uitsluitend lokale supportbundels | Geen online telemetriedienst, upload of extern geaudite privacygarantie |

De ingebouwde adapters worden gestart met `lab <naam> --python <echte-interpreter>
-- <adapteropties>`. Bijvoorbeeld:

```bash
cargo run -- lab backup-drill --python python3.12 -- \
  --database catalog.sqlite --archive-dir private-backups \
  --action watch --cycles 2 --interval-ms 25
cargo run -- lab vector --python python3.12 -- --db vectors.sqlite init
cargo run -- lab stdlib-api --python python3.12 -- --db stdlib-312.sqlite
cargo run -- lab transitive-resolver --python python3.12 -- \
  --input local-catalog.json --python-version 3.12
```

Maak de backupmap vooraf aan met uitsluitend eigenaarstoegang (`chmod 700`);
gebruik alleen een vertrouwde, bestaande SQLite-catalogus. Een status `PASS`
op een geselecteerde fixture mag nooit worden gelezen als een bewezen herstel
van willekeurige Python-software. Niet-ondersteunde versies, ontbrekende
bronnen en onveilige code blijven `UNKNOWN`, `PARTIAL`, `NOT_RUN` of `BLOCKED`.

## Benodigdheden

- Rust/Cargo (stable), voor bouwen van deze CLI.
- CPython 3.9 t/m 3.15, of een toekomstige versie uit het bijgewerkte manifest.
- [Ruff](https://docs.astral.sh/ruff/) voor `repair` (apart te installeren).
- Geen AI-model, internet of cloudaccount nodig voor de lokale MVP.

## Installeren en gebruiken

```bash
cargo build --release

# Linux x86_64: de ZIP bevat ook een vooraf gebouwde binary.
./dist/linux-x86_64/rust-python-healer --version
./dist/linux-x86_64/rust-python-healer scan pad/naar/project

# Controleert Python zonder de onderzochte code uit te voeren.
cargo run -- check pad/naar/script.py --python python3

# Analyseer een bewaard Python-traceback als tekst; voert niets uit.
cargo run -- trace pad/naar/traceback.txt
# Standaard worden paden, codefragmenten, functies en exceptionteksten
# verborgen. Alleen lokaal met bewuste vrijgave van gevoelige details:
cargo run -- trace pad/naar/traceback.txt --show-sensitive

# Lees package-metadata, Requires-Python en beperkte PEP 508-markers,
# zonder de package zelf te importeren of iets te installeren.
cargo run -- deps --python python3.11 --package numpy --package pandas
# Alleen deze opgegeven extras meetellen, zonder packages te installeren:
cargo run -- deps --python python3.11 --package requests --extra socks

# Controleer hashregels van werkelijk geïnstalleerde bestanden,
# zonder te claimen dat de wheel of uitgever is geauthenticeerd.
cargo run -- record --python python3.11 --package requests

# Lees pyproject.toml, setup.cfg en lockfiles statisch; voer setup.py niet uit.
cargo run -- project pad/naar/python-project --python python3.11

# CPython-AST: functies, imports, bronposities en mogelijke aanroepen.
cargo run -- ast pad/naar/script.py --python python3.11

# Analyseer expliciet vastgelegde herhalingen (JSON); voert geen testcode uit.
cargo run -- flaky pad/naar/retest-evidence.json --python python3.11

# Maak een onbevestigde metadata-SBOM zonder packages te importeren.
cargo run -- sbom --python python3.11
# Een gecontroleerde metadata-fixture onafhankelijk inventariseren:
cargo run -- sbom --only-metadata-dir --metadata-dir pad/naar/dist-info-root

# DAP-handshake en capabilityonderhandeling via stdin/stdout (geen live debugbackend).
cargo run -- dap

# Vergelijk vaste AST-, bytecode- en tracebackreferenties per CPython-minor.
cargo run -- version-regression --python python3.12

# Zes verplichte kwaliteitsdrempels voor extern getekende bewijsrapporten.
# De trustfile moet afzonderlijk beveiligd en beheerd worden.
cargo run -- qualify --policy policy.json --trust auditor-trust.json \
  --evidence signed-evidence.json --python python3.12

# Reproduceerbare propertytests met vaste seed en shrinking voor vertrouwde
# ingebouwde eigenschappen; voert geen externe Python-projectcode uit.
cargo run -- property --property mutant_double_equals_self \
  --seed 42 --cases 100 --python python3.12

# Statische veiligheids- en code-smellclassificatie; geen bronuitvoering.
cargo run -- static pad/naar/script.py --python python3.12
cargo run -- static --classify SEC001 --python python3.12

# Onderzoeksadapters zitten ingebed in de zelfstandige Rust-binary.
# De argumenten na '--' gaan uitsluitend naar de ingebouwde adapter.
cargo run -- lab dag --python python3.12 -- --manifest taken.json
cargo run -- lab graph --python python3.12 -- --db graph.sqlite init
cargo run -- lab abi-tags --python python3.12 -- \
  --wheel sample_pkg-1.0-py3-none-any.whl
cargo run -- lab role-router --python python3.12 -- \
  --roles config/agent_roles.json --tasks routing.json

# Scan parallel alle .py-bestanden in een project (zonder uitvoering).
cargo run -- scan pad/naar/project --workers 4 --limit 500

# 100 testgevallen per versie 3.9 t/m de nieuwste stabiele CPython.
# Ontbrekende interpreters krijgen NOT_RUN.
cargo run -- matrix pad/naar/script.py

# Voor een afwijkend interpreterpad (optie is herhaalbaar):
cargo run -- matrix pad/naar/script.py \
  --interpreter 3.9=/opt/python39/bin/python3.9

# Genereert, indien mogelijk, een nieuw bestand script.healed.py.
# Het origineel wordt nooit overschreven.
cargo run -- repair pad/naar/script.py --ruff ruff --python python3

# Bewaar metadata van lokaal geïnstalleerde packages (naam, versie, eisen).
cargo run -- catalog import-installed --python python3

# Indexeer afzonderlijke documentatiebestanden met expliciete herkomst.
cargo run -- catalog add docs/pandas.txt \
  --source official-docs --uri https://pandas.pydata.org/docs/ \
  --title "pandas documentation" --package pandas --version 2.3.0

cargo run -- catalog search "dataframe merge"
cargo run -- catalog stats
# Controleer de SQLite-database en de external-content-FTS-index.
cargo run -- catalog maintain --action check
# Repareer alleen de FTS-index; voert geen Python-projectcode uit.
cargo run -- catalog maintain --action rebuild
cargo run -- catalog maintain --action optimize

# Bewaar een WAL-consistente snapshot; bestaande bestanden worden geweigerd.
cargo run -- catalog backup --out knowledge-backup.sqlite
# Gebruik de sha256 uit de back-upuitvoer; herstelt alleen naar NIEUW bestand.
cargo run -- catalog restore --backup knowledge-backup.sqlite \
  --out knowledge-restored.sqlite --sha256 VERVANG_DOOR_ECHTE_SHA256

# Herken de Python-implementatie, native SOABI en free-threaded buildflag.
cargo run -- runtime --python python3.13
cargo run -- bench

# Controle op nieuwe officiële releases, zonder data te wijzigen.
cargo run -- update

# Veilige metadata-/documentatie-update, max. eenmaal per 24 uur.
cargo run -- update --apply --auto

# Optionele langlopende updatecontrole onder een procesmanager.
cargo run -- update --apply --watch
```

Alle resultaatgegevens verschijnen als JSON. `check` geeft exitcode 2 voor
ongeldige Python-code. `repair` maakt een kandidaat via **Ruff safe fixes**
en compileert het resultaat zonder uitvoering. Als Ruff niet kan parsen,
probeert een afzonderlijke conservatieve syntaxisregel een eenvoudige
ontbrekende `:` te herstellen. Andere syntax- en gedragsfouten kunnen
nog niet betrouwbaar automatisch worden gerepareerd.

`repair` houdt een persistente registratie bij van configuratie- en
bronhashes, vermijdt dubbele testuitvoeringen (tenzij `--retest`) en schrijft
alleen een kandidaat met een geslaagde compilatie naar een **nieuw** pad.
Een bestaande kandidaat met andere bytes wordt niet vervangen. Het programma
wijzigt **nooit** het oorspronkelijke script en noemt een kandidaat niet
"correct" of "winnaar" zonder het volledige bewijs.

## Nieuwe diagnosefuncties in v0.5

- `trace <bestand>` ontleedt bewaarde Python-tracebacks, herkent het laatste
  exceptiontype, stapelframes en de meest directe locatie, en geeft
  **voorzichtige suggesties** per foutcategorie. Het voert geen code uit en
  leest de in de traceback genoemde bronbestanden niet. Zonder herkenbare
  traceback is de status `NOT_RUN`; een suggestie is geen bewezen reparatie.
- `deps --python <interpreter> --package <naam>` inventariseert
  geïnstalleerde `.dist-info`-metadata zonder module-import. Een optioneel
  `--metadata-dir` accepteert een extra metadatafolder voor tests of analyse.
  De engine rapporteert `FOUND`, `MISSING` of `AMBIGUOUS` en toetst
  eenvoudige `Requires-Python`-voorwaarden als `>=3.9,<3.16`.
  **Niet-ondersteunde PEP 440-regels worden `UNKNOWN`**; transitive
  dependency-solving en daadwerkelijke runtimecompatibiliteit blijven
  `NOT_RUN` / `NOT_VERIFIED`. Geen package wordt geïnstalleerd.

Deze modules vormen de eerste uitbreiding richting een echte diagnostische
debugger; uitgebreide runtime-instrumentatie, complexe API-migraties en
autonome projectherschrijving zijn nog niet gebouwd.

## Nieuwe, daadwerkelijk geteste onderdelen in v0.8

- **`runtime`** leest alleen interpretermetadata (`sys.implementation`,
  `Py_GIL_DISABLED`, werkelijke GIL-status indien beschikbaar, SOABI).
  Oudere CPython, standaard CPython 3.13+ en free-threaded builds krijgen
  verschillende classificaties. Free-threaded en PyPy zijn **synthetisch
  geclassificeerd in unitfixtures**, niet met echte alternatieve interpreters
  gekwalificeerd; checklist F171/F174 blijft PARTIAL.
- **`catalog maintain`** controleert SQLite en FTS5 inclusief een harde
  `integrity-check` met external-content-vergelijking; `rebuild` en `optimize`
  hebben een transactie en opnieuw uitgevoerde integriteitscheck. Ook een
  bewust ontbrekend indexrecord wordt gevonden en hersteld (F222).
- **WAL-concurrency** is met vier gelijktijdige schrijvers en twee lezers
  getest, inclusief een opgelegd schrijfconflict, timeout en herstel (F221).
- Een afzonderlijke FTS5-microbenchmark met **10.000 synthetische documenten**
  haalde p95 **2,68 ms** bij 100 zoekherhalingen. Representativiteit en
  prestaties op echte grote Python-corpora zijn nog niet bewezen (F115 PARTIAL).
- **`catalog backup/restore`** maakt een SQLite-snapshot met alle
  gecommitte WAL-wijzigingen, berekent SHA256, weigert overschrijven en
  controleert de inhoud voor herstel. Scheduling, uitgebreide migraties,
  OS-beveiliging en disaster recovery zijn **nog open** (F080/F224 PARTIAL).
- **[Veiligheidsmodel](docs/SECURITY_MODEL_v0.11.md)** maakt bestaande
  maatregelen en ontbrekende sandbox-/supply-chaincontroles expliciet.

## Verder gebouwd in v0.9

- **F223 — transactionele schemamigraties.** Kennisdatabases gaan
  idempotent van schema 0/1 naar 2; een mislukte DDL-migratie blijft op de
  oude versie, terwijl een toekomstige onbekende versie wordt geweigerd.
  Behouden documenten en migratiehistorie worden apart gecontroleerd.
- **F186 — PEP 668-controle (gedeeltelijk).** `runtime` leest nu
  `EXTERNALLY-MANAGED` en venv-aanwijzingen zonder packages te installeren.
  Een beheerde globale installatie wordt als verboden gemarkeerd; tests op
  echte beheerde OS-distributies staan nog open.
- **Een reden bij elk open checklistpunt.** Alle **186** niet-afgevinkte
  F-ID's hebben direct onder hun regel een uitleg. De broncode-audit en
  drie nieuwe negatieve regressietests bewaken dat geen reden verdwijnt.
  Bij F039, F107, F108 en F204–F206 staat de mislukte OS-/netwerkisolatie
  expliciet als blokkade.

## Verder gebouwd in v0.10

- **F185 — herkomst van directe packageinstallaties (gedeeltelijk).**
  `deps` inspecteert een PEP 610 `direct_url.json` begrensd tot 32 KiB,
  herkent VCS- of editable-installatieherkomst en geeft alleen schema,
  host, type en een URL-hash terug. Inloggegevens, lokale paden en
  querytokens worden niet integraal in rapporten opgenomen. Deze metadata
  is geen cryptografische provenance-attestatie.
- **F202 — onbetrouwbare metadata (gedeeltelijk).** Malformeerde JSON,
  te grote metadata en symlinks naar `direct_url.json` worden geweigerd.
  Zipbomdetectie en volledige adversariële supply-chain-audits ontbreken.
- **Checklistredenen blijven verplicht.** De 186 open F-ID's worden ook
  onder Python 3.9–3.15 op de aanwezigheid van hun uitleg gecontroleerd.

## Verder gebouwd in v0.11

- **F048 — levenscycluswaarschuwingen.** `runtime` toont de CPython-status
  `END_OF_LIFE`, `SECURITY_ONLY` of `BUGFIX_AND_SECURITY` met officiële
  bron, controlepeildatum en waarschuwing. Voor een onbekende toekomstige
  minorversie wordt **geen support verzonnen** maar `UNKNOWN` gerapporteerd.
  De planning is een momentopname en kan bij een volgende Python-release
  worden gewijzigd; automatische actualisering van deze specifieke tabel
  is nog een open taak.
- **F105/F203 — beveiligde Linux-projectscans (gedeeltelijk).** `openat2`
  opent Python-bronnen binnen de projectroot zonder symlinks of mountovergangen.
  Hardlinks worden geweigerd, en Python compileert alleen een tijdelijke
  broncode-snapshot. Een geweigerde bron wordt `NOT_RUN`, niet `PASS`.
  Linux-symlink- en hardlinkaanvallen hebben unit-, integratie- en
  versiegebonden negatieve tests gekregen. Andere OS'en en onafhankelijke
  race-audits zijn nog niet geverifieerd.
- **Elke open functie heeft nog steeds een reden.** De inventaris telt nu
  **75 geteste functies, 19 gedeeltelijke functies en 185 open punten**.

## Verder gebouwd in v0.12

- **F219 — cachevernieuwing en tombstones (gedeeltelijk).** De updater
  verwijdert niet langer alleen bronnen uit het geheugen: wanneer een
  eerder gecontroleerde package uit de watchlist verdwijnt, verdwijnen
  de bijbehorende lokale documenten en ETags transactioneel; een tombstone
  blijft bewaard. Documenten die de gebruiker zelf toevoegde met dezelfde
  URL blijven intact. Een terugkerende bron wordt opnieuw geïndexeerd.
  Een HTTP 304 wordt alleen aanvaard als een eerdere ETag en een
  SHA256-correcte lokale kopie bestaan. Corrupte caches worden opnieuw
  opgehaald. Nog niet alle historische caches en live bronnen zijn gedekt.
- **F200 — geïnjecteerde updatefouten (gedeeltelijk).** Tests bootsen een
  SQLite-fout en een mislukte manifestvervanging na. De updater kan na
  een onderbroken manifestvervanging herstellen zonder door de 24-uurs
  update-TTL ten onrechte te worden overgeslagen.
- **Betere resourcereiniging.** SQLite-verbindingen worden ook bij
  uitzonderingen gesloten; waarschuwingstests op Python 3.15 zijn schoon.
- **Tests:** vijf aanvullende updatergevallen per interpreter, dus
  **70 × 7 = 490** Python-tests op de zeven echte minorversies.

## Verder gebouwd in v0.19 — 100 van 260 gecontroleerde functies

**22 nieuw afgevinkte functies:** F040 (property/fuzz/mutation/metamorfisch),
F070 (documentlicentie/herkomst), F078 (versiegebonden relationele graaf),
F096 (statische regels), F118–F121 (resource-/kost-/queuemeting en 36 rollen),
F124 (DAG-volgorde), F169 (subinterpreters vanaf 3.14), F175 (ABI/wheel-tags),
F194–F195 (reproduceerbare shrinking en gerichte fuzzing),
F212–F213 (releasehistoriek en versiegebonden secties), F217–F218
(bronconflicten, licenties/citatiequota), F227–F228 (provenancegraaf en
experimentarchivering), F231 (data-only taakqueue), F238 (releasemetrieken)
en F240 (HMAC-beschermde beslisaudit).

De nieuwe `lab`-subcommand biedt ingebedde Python-adapters aan via de
Rust-binary. Alle adapters gebruiken geselecteerde, begrensde bewijsdata;
de 36 rollen zijn **een routeringsplan, geen 36 actieve AI-agenten**.
Subinterpretercontrole scheidt namespaces, maar is **geen OS-sandbox**.
Bron-HMAC's bewijzen lokale operatorautorisatie, **niet** de identiteit van
een externe uitgever. Snapshot- en auditintegriteit zijn lokaal, **niet**
onafhankelijk WORM/geankerd. De statistieken voor externe kandidaten zijn
gerapporteerde gegevens, geen bewezen autonome herstelkwaliteit.

**Nieuw gedeeltelijk:** F117, F164, F167, F199, F214–F215, F235 en F245.
Een geautoriseerde example-compile- en `.pyi`-indexadapter, een
read-only async-traceparser en een afzonderlijke wheel/binary-distributiebouwer
zijn gebouwd. Volledige unknown-code-executie, live forkserver op deze host,
API-rename-semantiekinferentie, originele uitgeversignaturen en multi-OS-
releasevalidatie ontbreken daarom nog.

**Bewijs:** 542 × 7 = **3.794 geslaagde Python-tests**, **57 Rust-tests**,
**84 offline Rust-labchecks**, **700/700 actuele taalcases**, Rust-releasebuild
en strikte Clippy geslaagd. Historische 413 volledige CLI-matrixgevallen
blijven in v0.18-bewijs bewaard. In v0.19 zijn **35 onafhankelijke FTS5-rondes
met gecorrigeerde per-ronde en globale p95-gates** opnieuw geslaagd, maar de
nieuwe online end-to-end matrix is wegens een geblokkeerde externe verbinding
**niet** opnieuw volledig uitgevoerd. Er wordt geen 100%-productcorrectheid
geclaimd. In v0.19 waren van de 260 eisen **100 IMPLEMENTED_TESTED**, 38 `PARTIAL`,
108 `NOT_IMPLEMENTED`, zeven `NOT_RUN` en zeven `BLOCKED`; toen **160 open**.

## Verder gebouwd in v0.18 — drie volledig afgevinkte functies

- **F151 IMPLEMENTED_TESTED:** nieuw `dap`-commando gebruikt DAP
  `Content-Length`-framing, veilige initialisatie, capabilityonderhandeling
  en afsluiting. DAP heeft bewust geen vaste protocolversieonderhandeling:
  features worden via capabilities onderhandeld. Ongeldige input,
  `launch`, `attach` en `evaluate` worden veilig geweigerd. Echte live
  debugging, breakpoints en VS Code/PyCharm-conformantie blijven open.
- **F180 IMPLEMENTED_TESTED:** `version-regression` vergelijkt ingebedde,
  per CPython 3.9–3.15 vastgelegde AST-/bytecode-/tracebackreferenties.
  Een gewijzigde hash krijgt `REGRESSION`; een onbekende toekomstige versie
  krijgt `NOT_RUN`. De vaste tracebackfixture is vertrouwd: projectcode
  wordt niet uitgevoerd. Referenties zijn niet cryptografisch ondertekend.
- **F237 IMPLEMENTED_TESTED:** `qualify` weigert ranking zonder zes
  verplichte, vooraf bepaalde kwaliteitsgrenzen en aparte HMAC-verificatie
  van meetrapporten: veiligheid, correctheid, snelheid, betrouwbaarheid,
  compatibiliteit en toekomstbestendigheid. Het geeft maximaal één reserve
  en `NO_WINNER` bij onvoldoende bewijs. Een getekend rapport bewijst **niet**
  dat de externe auditor de tests echt heeft uitgevoerd; er is geen
  vrijgave of automatische bronuitvoering (`release_authorized=false`).
- **F240 PARTIAL:** een besluitregistratie met beleids- en bewijs-SHA256,
  primaire kandidaat, reserve of `NO_WINNER` is beschikbaar; duurzame
  onwijzigbare auditopslag en onafhankelijke releaseautorisatie ontbreken.
- **Nieuw controlebewijs:** 260 producteisen, **78 afgevinkt**, 33 gedeeltelijk,
  135 nog niet gebouwd, 7 `NOT_RUN` en 7 geblokkeerd. Nog **182 open**;
  **485 geïnventariseerde codefuncties** en **25 CLI-(sub)commando's**.

## Verder gebouwd in v0.17

- **F091/F097 — AST en mogelijke aanroepen (gedeeltelijk).** Nieuw `ast`
  inspecteert begrensde Python-bronnen zonder ze uit te voeren en noemt
  mogelijke call-edges nadrukkelijk onbevestigd. CST, control-flow en
  werkelijk bewezen callgraph ontbreken.
- **F183 — dependencygroepen/extras/buildmetadata (gedeeltelijk).** `project`
  leest vanaf CPython 3.11 via `tomllib` begrensde groepen en recursieve
  includes; cycli, conflictnamen en te grote invoer worden afgewezen.
  Op 3.9–3.10 worden die structuren niet volledig geparseerd of opgelost.
- **F198 — flaky testbewijs (gedeeltelijk).** Nieuw `flaky` analyseert
  herhaalde meetrecords, eist expliciete RETEST en voorkomt PASS op
  tegenstrijdige of ontbrekende metingen. Geen geïsoleerde testsessie
  of gedragsequivalentiebewijs.
- **F209 — metadata-SBOM (gedeeltelijk).** Nieuw `sbom` inventariseert
  packageversies, SHA256 en gehashte herkomst-URL's; credentialgegevens,
  package-uitvoering, dependency-installatie en een schijnbaar afgeronde
  kwetsbaarheids- of uitgeversverificatie worden geweigerd.
- **Checklist:** 260 producteisen, 75 volledig getest in beperkte scope,
  32 gedeeltelijk, 139 niet gebouwd, 7 niet uitgevoerd en 7 geblokkeerd;
  **185 nog open**. Alle **403 codefuncties** en **22 CLI-(sub)commando's**
  zijn geregistreerd in het broncode-auditbestand.

## Verder gebouwd in v0.16

- **F057 — PEP 440-vergelijkingen (gedeeltelijk).** Ondersteunt nu
  compatibele versies (`~=`), epochs, `===`, release-nulsegmenten en
  beperkte clausules. Een fout bij `>3.9` met Python 3.9.25 is hersteld.
  Onbegrepen ontwikkel-/pre-/postversies en andere complexe constraints
  blijven `UNKNOWN`; er is nog geen volledige transitive resolver.
- **F060 — projectbestanden (gedeeltelijk).** Nieuw `project`-commando
  detecteert statisch `pyproject.toml`, `setup.py`, requirementsbestanden
  en gangbare lockfiles met begrensde SHA256-inventarisatie.
  Python 3.11+ gebruikt `tomllib`; Python 3.9–3.10 geeft slechts
  onbevestigde tekstkandidaten. Geen usercode-uitvoering of lock-validatie.
- **F187 — Wheel-RECORD-integriteit (gedeeltelijk).** Nieuw `record`-commando
  verifieert SHA256 en grootte van aanwezige packagebestanden binnen strikte
  grenzen; weigert ongeldige hashes, traversal, symlinks en hardlinks.
  De aanwezigheid van een kloppende hash is geen cryptografisch bewijs
  voor een betrouwbare uitgever of volledige installatie.
- **Bewijs:** 260 functies, 75 afgevinkt, 27 gedeeltelijk en 185 open;
  332 codefuncties en 19 CLI-(sub)commando's geregistreerd.
  **103 × 7 = 721 Python-helpertests**, **52 × 7 = 364**
  CLI-/benchmarks, 700 taalchecks en 43 Rust-tests.

## Verder gebouwd in v0.15

- **F058 — PEP 508 dependency-markers (gedeeltelijk).** Zonder `eval()` of
  installatie leest een beperkte AST-parser voorwaardelijke `Requires-Dist`-
  regels en geeft per dependency `SATISFIED`, `UNSATISFIED`, `UNKNOWN` of
  `NOT_DECLARED`. Numerieke Python-minor-/patchversies, `sys_platform`,
  `os_name`, overige standaardplatformvelden, `and`/`or` en expliciet
  geselecteerde `--extra`-namen worden ondersteund. Onbegrepen PEP 440-
  operatoren, geavanceerde lockfilevariabelen en ambigu metadata blijven
  `UNKNOWN`. Er is **geen** volledige dependency-solver of packageinstallatie.
- **Checklist en bewijs:** 260 items; 75 afgevinkt, 24 gedeeltelijk,
  185 open met reden. 293 functies geregistreerd. **82 × 7 = 574**
  Python-helpertests, **48 × 7 = 336** CLI-/benchmarktests,
  700 taalchecks en **41 Rust-tests**.

## Verder gebouwd in v0.14

- **F207 — privégegevens in diagnoses (gedeeltelijk).** `check` geeft geen
  ruwe compilerexceptiondetails terug. `trace` verbergt standaard het pad,
  de functie, bronregels en exceptionboodschap; een SHA256-padidentifier laat
  frames vergelijken. Voor lokaal gebruik bestaat een bewuste
  `--show-sensitive`-optie. Andere log-/metadatapaden zijn nog niet volledig
  doorgelicht; geen algemene privacygarantie.
- **F208 — onbetrouwbare kennis (gedeeltelijk).** Cataloguszoekresultaten
  worden als onbetrouwbare data gemarkeerd, niet als uitvoerbare instructies.
  Negatieve prompt-injectionfixtures zijn zonder uitvoeren getest. Een
  toekomstige AI-consument vereist nog een aparte, afgedwongen grens.
- **F210 — Python-audithook (gedeeltelijk).** De compile-only-helper registreert
  alleen tellingen van `open`, `compile` en `exec`, nooit auditargumenten of
  broncode. Het rapport vermeldt expliciet dat dit **geen sandbox** is.
- **F202 — metadata- en queryquota (gedeeltelijk).** Onredelijk grote
  catalogusmetadatavelden, NUL-waarden en FTS-queries boven 512 bytes/16
  termen worden geweigerd. Zipbommen en algemene fuzzveiligheid blijven open.
- **Teststand:** 260 checklistitems, 75 afgevinkt, 23 gedeeltelijk en 185
  open met reden; 280 codefuncties geregistreerd. 76 × 7 = 532
  Python-helpertests, 47 × 7 = 329 versiegebonden CLI-/benchmarkcontroles,
  700 taalchecks en 40 Rust-tests.

## Verder gebouwd in v0.13

- **F219 — ook historische updatercaches herstellen (nog gedeeltelijk).**
  Oude databases met geregistreerde ETags worden herkend wanneer het nieuwe
  bronregister ontbreekt. De updater controleert nu alle gecachte versies
  per gevolgde bron. Een corrupte oude packageversie wordt pas na een
  succesvolle herdownload uit FTS5 verwijderd. Documenten met een andere
  bronnaam worden niet aangetast. Onder alle zeven minorversies getest.
- **F116 — onafhankelijke FTS5-snelheidsrondes (gedeeltelijk).** Per Python
  3.9–3.15 worden vijf aparte SQLite-databases met ieder 10.000 synthetische
  documenten opgebouwd. Elke ronde meet 30 queries; mediane/p95-latenties,
  totale metingen en een vooraf bepaalde 50 ms-p95-grens
  worden per interpreter opgeslagen, samen met de documentopbouwtijden.
  Minder dan vijf rondes wordt geweigerd.
  De volledige Rust-herstelpijplijn en realistische externe API-corpora zijn
  hiermee nog niet gekwalificeerd.
- **Checklist en testbewijs:** 260 productfuncties, 75 afgevinkt,
  20 gedeeltelijk, 185 open met reden. **74 × 7 = 518 Python-helpertests**,
  **42 × 7 = 294 versiegebonden CLI-/benchmarkcontroles** en 700 taalchecks.

## 100 tests per Python-versie

`python/version_suite.py` heeft **precies 100 unieke gevallen per interpreter**:

| Categorie | Tests | Voorbeelden |
|---|---:|---|
| Geldige syntax | 30 | `async`, functies, classes, comprehensions |
| Ongeldige syntax | 20 | Syntaxfouten, scope, inspringing |
| Versiegebonden syntax | 20 | `match` (3.10), `except*` (3.11), typeparameters (3.12), t-strings (3.14) |
| Vertrouwde runtimefixtures | 20 | Containers, numeriek, generatoren, `decimal` |
| Standaardbibliotheek | 10 | `json`, `ast`, `pathlib`, `collections`, `re` |

De matrix voert die tests voor elke beschikbare CPython-minorversie apart uit,
en voegt voor toekomstige stabiele versies automatisch weer 100 geplande
tests toe. Bij een ontbrekende interpreter wordt **NOT_RUN** geregistreerd.
Het zijn geselecteerde gedrags-/taaltests, geen bewijs van elke package-API.

In de huidige omgeving: **700/700 PASS** onder echte CPython-interpreters:
3.9.25, 3.10.22, 3.11.17, 3.12.14, 3.13.16, 3.14.8 en 3.15.0.
De geïnstalleerde patchniveaus zijn niet noodzakelijk de meest recente
microreleases. Via `uv python install 3.9 3.10 3.11 3.12 3.13 3.14 3.15`
kunnen beschikbare patchversies worden geïnstalleerd in een testomgeving.

## Elke geïmplementeerde functie testen op iedere versie

Naast de taalsuite is er nu een **aparte end-to-end functiematrix** in
`tools/feature_matrix.py`. De runner start de daadwerkelijk gebouwde Rust-
binary met een afzonderlijk gekozen CPython-interpreter en een tijdelijke
werkmap en databases per versie. Er zijn **59 controlepunten per versie**:

- Interpreteridentiteit, geldige/ongeldige diagnose, nooit uitvoeren van
  onderzochte broncode en weigeren van ontbrekende bestanden.
- Tracebackanalyse op echte, door de gekozen interpreter geproduceerde
  exceptions; geketende exceptions, `SyntaxError` en ongeldige tracebacks.
- Package-metadata-inspectie: compatibele, incompatibele, onbekende en
  ontbrekende packages; `.pth` wordt niet uitgevoerd.
- Projectscanner (gemengde resultaten, genegeerde `.venv`, schone projecten,
  bestandslimieten en lege projecten zonder valse PASS).
- Ruff-safe-fix, ontbrekende-dubbelepuntfix, ongewijzigd origineel,
  deduplicatie, `--retest`, output-overschrijvingsbeveiliging en ontbrekende Ruff.
- SQLite-variantregister (`bench`) en kenniscatalogus (toevoegen, FTS5-zoeken,
  statistieken, import van de gekozen versie, afwijzen lege zoekterm).
- Automatische update-TTL via de echte Rust-CLI, afwijzen van `--watch`
  zonder `--apply`, alle 48 helpertests, en de volledige taalmatrix.
- Complete codefunctie-inventaris en de 260-punten-productchecklist bewaken.
- Runtimeclassificatie, ontbrekende interpreter, database-indexintegriteit en
  WAL/SHA-backup/restore inclusief afwijzing van gemanipuleerde invoer.
- Transactionele schemaupgrade 1 naar 2 met behoud van documentgegevens;
  controle op package-omgevingsbeleid en redenen voor alle open F-ID's.
- PEP 610-origininspectie met redactie van credentials, URL-paden en tokens.
- Linux-pathbescherming tegen externe symlinks en hardlinks; lifecycle-
  waarschuwingen voor EOL- en security-only-interpreters.
- Privacybehoud voor compilerfouten en tracebacks, expliciete vrijgave,
  audit-eventtellingen zonder argumenten, onbetrouwbare kennislabels en
  begrensde catalogusmetadata/FTS-queries.
- Conservatieve PEP 508-tristatemarkers met platform-/versiefilters en
  expliciete extras; geen package-import of installatie.
- Begrensde PEP 440-versiespecificaties, wheel-`RECORD`-hashvergelijking,
  statische project-/lockfile-inventarisatie zonder `setup.py`-uitvoering.
- Statische AST-symbool-/aanroepkandidaten, dependencygroepen/extras,
  expliciete flaky RETEST-registratie en afgeschermde SBOM-metadata.
- DAP-framing/capabilityhandshake zonder code-uitvoering, per versie
  vastgelegde AST/bytecode/traceback-regressies en zes getekende
  kwaliteitsdrempels zonder automatische releasepromotie.

Uitvoeren vanuit de bronmap, na installeren van de 7 interpreters en Ruff:

```bash
cargo build --release
python3 tools/feature_matrix.py \
  --binary target/release/rust-python-healer \
  --ruff /pad/naar/ruff \
  --json evidence/FEATURE_MATRIX_local.json
```

De runner leest de versierange uit `config/versions.json` en kan met
`--interpreter 3.9=/pad/python3.9` alternatieve interpreterpaden gebruiken.
De workflow `.github/workflows/compatibility.yml` bevat ook een afzonderlijke
CI-job die alle interpreters uit het manifest installeert en vervolgens
dezelfde functiematrix bij push of pull request draait. **Deze CI-job is
toegevoegd, maar in deze sessie niet op GitHub uitgevoerd**; de laatste
volledig uitgevoerde netwerkgevoelige functiematrix dateert uit v0.18.
Een v0.19-herhaling was wegens de vereiste externe verbinding niet toegestaan.
Na een officiële kennisupdate die bijvoorbeeld Python 3.16 toevoegt, wordt
de nieuwe versie automatisch **gepland** in de suite en functiematrix. Ze
krijgt pas PASS als er een echte bijpassende interpreter geïnstalleerd is en
alle controles slagen; de tool installeert of vertrouwt nieuwe uitvoerbare
bestanden niet automatisch. De updater zelf is per interpreter via mocks
getest op releasecontrole, update-import, verse én verlopen 24-uurs TTL,
foutafhandeling en detectie van een toekomstige 3.16-release. Ook is getest
dat een toekomstige 3.16-compatibiliteitsrij zonder echte interpreter
`NOT_RUN` blijft.

**Reikwijdte:** dit zijn tests van alle huidige gebruikersgerichte Rust-CLI-
functies op geselecteerde fixtures, geen uitputtende tests van alle branches,
alle packagefuncties, native ABI's, besturingssystemen of arbitraire projecten.
De echte netwerkcontrole is niet zevenmaal herhaald; de helpertests gebruiken
gecontroleerde HTTP-mocks. De oneindige `--watch`-loop en het vervangen van
de Rust-binary zijn niet end-to-end getest; binary-self-update is uitgeschakeld.

## Functiechecklist: niets vergeten (v0.19)

**[FUNCTION_CHECKLIST.md](docs/FUNCTION_CHECKLIST.md)** bevat **260
afzonderlijk genummerde productfuncties**, gegroepeerd in 26 onderdelen.
Elke functie is aangevinkt als ze op geselecteerde tests werkelijk gebouwd
en gecontroleerd is; de rest staat expliciet op PARTIAL, NOT_IMPLEMENTED,
NOT_RUN of BLOCKED. De uitbreiding v0.7 voegt **110 expliciete hiaten** toe
vanuit Debug Adapter Protocol, async/concurrency, free-threaded Python,
subinterpreters, packaging-lockfiles, packageattestaties, beveiliging,
testkwaliteit, databaseherstel en wetenschappelijke/web-ecosystemen. De lijst
is een onderhoudbare baseline en groeit bij nieuwe Python-versies, PEPs en
aanvullende wensen. **100 items zijn op afgebakende fixtures getest en
afgevinkt; 160 blijven expliciet open.**

De afzonderlijke **[gap-analyse vanuit elf invalshoeken](evidence/GAP_ANALYSIS_v0.7.md)**
benoemt per cluster de ontbrekende functies, risico's, prioriteiten en
officiële technische bronnen. **Dit zijn aanvullende ontwikkeltaken, geen
110 nieuw geïmplementeerde functies.**

Los daarvan bevat `config/code_symbol_inventory.json` de volledig
geïnspecteerde namen van alle functies/methoden in `src/`, `python/`,
`tools/` en `tests/` (inclusief helpers en testfuncties), plus alle **28
Rust-CLI-(sub)commando's**. Een nieuwe functie of CLI-commandodeclaratie
zonder bijgewerkte inventaris laat deze audit **falen**:

```bash
python3 tools/audit_function_checklist.py --check
# Bekijk de actuele codefuncties, zonder bestanden te wijzigen:
python3 tools/audit_function_checklist.py --dump-symbols
```

De audit is opgenomen in de Python-unittests, de versiegebonden
functiematrix en de CI-workflow. Een groene audit betekent **volledigheid
van het code-register**, niet dat alle 260 geplande productfuncties klaar zijn.

## Kennis-self-updater

De Python-updater onder Rust-regie ondersteunt:

- Nieuwste stabiele release detecteren via de officiële Python-downloadpagina.
- Per versie de officiële “What's New”-documentatie opnieuw inlezen.
- Versioned PyPI-metadata voor een configureerbare package-watchlist ophalen.
- ETags, SHA256, limieten en HTTPS-bronallowlisting; een ongeldige bron laat de
  bestaande releaseversie ongemoeid.
- Transactionele SQLite-updates en een instelbare 24-uurs TTL; `--watch` voor
  een beheerd langlopend controleproces.

Een live proef heeft **zeven Python-versiedocumenten en Ruff-package-metadata**
in de kennisindex opgeslagen. Een daaropvolgende automatische ronde sloeg
de bronnen terecht over wegens de TTL.

Dit werkt voor **kennisupdates**, niet voor willekeurige automatische
software-installaties. **Het Rust-programma zelf vervangen blijft uitgeschakeld**
totdat een ondertekend releasekanaal, rollback en securityverificatie bestaan.

## Twee fysieke databases, uitbreidbaar naar vier

| Laag | Status | Technologie | Inhoud |
|---|---|---|---|
| Kennisindex | In code aanwezig | SQLite + FTS5 | Versie-, bron- en hashgebonden documentatie en package-metadata |
| Experimentenregister | In code aanwezig | SQLite (WAL) | Unieke kandidaten, evaluaties, PASS/FAIL/NOT_RUN, tijden, logs |
| Semantisch zoeken | Ontwerp | Qdrant of lokaal vectorformaat | Contextuele zoekresultaten, gefilterd op Python/packageversie |
| Analytisch magazijn | Ontwerp | DuckDB | Historische benchmarks en trends over veel runs |

Geen database "leert" op zichzelf alle Python-API's. Package-updates,
deprecations en documentatie moeten met herkomst, licentie, datum en versie
worden geïmporteerd; een retrievallaag haalt alleen relevante bronnen op.
Er is **geen** onbeperkte internetcrawler, AI-reparateur, package-installer
of veilige uitvoering van onbekende gebruikerscode in dit prototype.

## Veiligheidsgrenzen

- Compile-only validatie via Python `-I -S -B`; er is geen `exec`, module-import
  of uitvoering van de doelcode.
- Ruff krijgt `--isolated` en uitsluitend gewone `--fix` (geen `--unsafe-fixes`).
- Vertrouwde subprocessen hebben tijd- en uitvoergroottelimieten.
- Projectscan volgt geen symlinks en slaat `.venv`, `node_modules`, cache- en
  buildmappen over; een lege scan wordt geen PASS. Op Linux openen
  bestands-snapshots met `openat2` onder de root zonder symlinks of hardlinks;
  op andere OS'en is de TOCTOU-weerstand nog niet bewezen.
- Kandidaten blijven gescheiden; zonder gedragstests wordt **geen** definitieve
  correctheid of release toegelaten.
- Niet vertrouwde tests of Python-programma's mogen pas in een **daadwerkelijk
  geïsoleerde** sandbox draaien. Alleen een timeout is geen sandbox.
- Er is nog geen volledige geheugen-/CPU-isolatie, rollback, multi-OS
  compatibiliteitsaudit of onafhankelijke securityaudit. Bubblewrap kon in
  deze omgeving geen namespace maken en werd daarom niet gebruikt voor
  onbekende code.

## Testen

```bash
python3 -m unittest discover -s tests -v
cargo test
cargo clippy --all-targets -- -D warnings
# Opt-in integratiechecks met daadwerkelijk geïnstalleerde Ruff:
RPH_RUFF_BIN=/pad/naar/ruff cargo test --all-targets -- --include-ignored
```

In de leveromgeving: **542/542 Python-/SQLite-/updater-/dependency-/registertests per versie**
(**3794/3794** over zeven interpreters), **57/57 Rust-tests (inclusief Ruff)**
en **84/84 offline Rust-adapterchecks** geslaagd. Het historische v0.18-
bewijs toont daarnaast **413/413 volledige functie-/benchmarkchecks**,
**700/700 CPython 3.9–3.15-curatiecases** in de historische v0.19-matrix, en
vijf onafhankelijke FTS5-rondes per interpreter. De online-gevoelige
v0.19-functiematrix is `NOT_RUN`.
Rust-releasebuild en strikte Clippy zijn eveneens **PASS op Linux**.
De binary is afzonderlijk uit de bronmap gekopieerd en op een andere
werkdirectory getest met `matrix` (700/700) en `update --auto` (TTL).
De Linux-binary vereist een compatibele Linux x86_64/GLIBC-omgeving;
Windows/macOS distributies zijn niet gebouwd.
Volledige project-/package-/OS-/sandboxkwalificatie blijft **NOT_RUN**.
Zie [ARCHITECTURE.md](docs/ARCHITECTURE.md) voor de
kritieke keten, varianten, vooraf vastgelegde scorecriteria en 36 geplande
specialistenrollen.

