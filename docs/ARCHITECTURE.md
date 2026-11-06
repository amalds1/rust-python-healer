# Ontwerp, bewijsregime en uitvoeringsplan

## Verifieerbare uitvoering v0.22

De v0.21-baseline van 175/260 is met **25 nieuwe, beperkte en lokaal
testbare functies** uitgebreid tot exact **200/260**. De 60 open punten
blijven expliciet verdeeld in 28 `PARTIAL`, 18 `NOT_IMPLEMENTED`, 7
`NOT_RUN` en 7 `BLOCKED`; geen onbekende sandboxbevoegdheid wordt
verondersteld. De afzonderlijke inventory telt **2.686** functies/methodes
in **157** source- en testbestanden.

Nieuwe kennis-/package- en beveiligingsadapters zijn data-only; de
echte DAP-runtime, resource-limit- en AES-GCM-cryptoproeven draaien
uitsluitend vertrouwde harde testfixtures. Rust orkestreert de veilige
`lab`-CLI-adapters zonder automatisch onbekende broncode te starten.
De cryptografisch geverifieerde lokale canary uit v0.21 bewijst nog
geen Rust-binary-self-updater of identiteit van een publieke uitgever.

De **36 agentrollen** zijn geconfigureerde *planningsrollen*, geen
claim van 36 onafhankelijke actieve modellen. Het in v0.21 gebouwde
procesduo voor het dubbele lokale bewijs heeft geen externe release-
autorisatie; geen enkele zes-assige gate mag een ontbrekende test als
PASS registreren. Zie `evidence/VALIDATION_v0.22.md` voor de concrete
per-minorresultaten, begrenzingen en bewijscategorieën.

## Verifieerbare uitvoering v0.21

De checklist is na 50 nieuwe, begrensde en zelfstandig geteste functies
precies **175/260 afgevinkt**. Nog **85** hebben verplicht een concrete reden
(`PARTIAL` 42, `NOT_IMPLEMENTED` 29, `NOT_RUN` 7, `BLOCKED` 7).
Een afzonderlijke geïnventariseerde lijst telt **2.259** broncodesymbolen in
**141** bestanden; `tools/audit_function_checklist.py --check` faalt
bij ongedocumenteerde wijzigingen of een ontbrekende open-reden.

De Rust-CLI is het beheerproces; expliciet ingebouwde Python-adapters
leveren beperkte versiebewuste semantiek. Het testprotocol gebruikt de
zeven echte minor-versies 3.9–3.15, echte Python-debugtraces van
vertrouwde fixtures, subprocessen voor afzonderlijke lokale auditeurs,
een offline wheelinstallatie en cryptografisch gecontroleerde lokale
canary-updates. Geen van deze voorzieningen mag zomaar onbekende
gebruikerscode uitvoeren, productie-deploys autoriseren of toekomstige
Python-versies als getest aanmerken. Voor de zes kwaliteitsassen
geldt strikt `NO_EVIDENCE=NO_PASS`; een lokaal ondertekend dossier
is geen identiteitsbewijs van een externe auditor. De volledige
kwalificatie staat in `evidence/VALIDATION_v0.21.md`.

## Doel en beperkingen

De bedoelde eindtoestand is een **Rust-orchestrator** voor Python-projecten:
fout lokaliseren, relevante regels en packageversies ophalen, onafhankelijke
herstelkandidaten maken, in een veilige geïsoleerde kopie testen, vergelijken,
en pas daarna met expliciete releasebevoegdheid toepassen.

Rust versnelt orchestration, indexing en concurrente scheduling. Het kan niet
zonder meer garanderen dat een automatisch herschreven Python-programma
semantisch juist is. Dynamische imports, netwerk, database-toestand, verborgen
vereisten en native extensions maken "alle libraries kennen" onhaalbaar als
een vaste eenmalige training. **Versiegebonden retrieval + verificatie** is
de schaalbare aanpak.

### Productfuncties en codefuncties gescheiden beheren (v0.7)

De canonieke checklist `docs/FUNCTION_CHECKLIST.md` bevat **260 unieke
functie-eisen** in 26 clusters: debugging, herstel, versiecompatibiliteit, packagebeheer,
kennisupdates, meerdere databases, sandboxing, benchmarking, agentrollen,
IDE-integratie en distributie. In v0.7 zijn 110 vergeten scenario's toegevoegd,
onder meer DAP, async, free threading, subinterpreters, PEP 751-lockfiles,
PyPI-attestaties, procesisolatie, testdeterminisme en package-adapters.
Elke eis heeft een stabiele F-ID en een
expliciete status; de zichtbare checkbox wordt uitsluitend bij een
geïmplementeerde én in gecontroleerde fixtures geteste functie aangevinkt.

De tweede inventaris, `config/code_symbol_inventory.json`, bewaart iedere
gedefinieerde functie/methode uit de huidige Rust- en Python-broncode en
tests, momenteel inclusief 25 CLI-(sub)commando's. `tools/audit_function_checklist.py --check` vergelijkt deze lijst
op naam en pad met de werkelijk aanwezige declaraties. Bij een nieuw,
verwijderd of hernoemd symbool faalt de audit tot de inventaris bewust is
bijgewerkt; ook dubbele F-ID's en misleidende vinkjes worden geweigerd.
De controle is opgenomen in de unittests, CLI-versiematrix en CI-configuratie.

**Grenzen:** het broncode-register is automatisch volledig voor de gekozen
bestandsset en herkenbare `fn`/`def`-declaraties, maar is geen compiler-
semantisch bewijs voor macro's, dynamisch gegenereerde code of externe
Python-/PyPI-API's. De 260 productfuncties zijn een versieerbare baseline,
geen claim dat alle denkbare toekomstige functies reeds bekend zijn.

### Uitvoering v0.8 (verifieerbare tussenstap)

De nieuwe Rust-CLI bevat `runtime` (alleen Python-implementatie- en
buildmetadata) en `catalog maintain`, `catalog backup` en `catalog restore`.
FTS5-integriteitscontrole met `rank=1` controleert ook de externe brontabel;
een indexrebuild en optimalisatie worden in een transactie uitgevoerd.
SQLite `VACUUM INTO` maakt een consistente snapshot, inclusief gecommitte
WAL-inhoud. Elke snapshot krijgt SHA256; herstel weigert afwijkende hashes
en reeds bestaande doelbestanden. De Python-runtimeprobe herkent
free-threaded-buildmetadata, maar **echte free-threaded CPython/PyPy-tests
zijn niet uitgevoerd**. Zie `docs/SECURITY_MODEL_v0.8.md` voor veiligheidsgrenzen.

Nieuw v0.8-bewijs: **36 CLI-cases × 7 echte CPython-versies = 252 PASS**;
**52 Python-helpers × 7 = 364 PASS**; **700 taalgevallen PASS** en **28
Rust-unit-/integratietests PASS**. Checklist F221 en F222 zijn naar
IMPLEMENTED_TESTED verplaatst; F080, F115, F171,
F174, F201 en F224 zijn PARTIAL. **73 van 260 productfuncties** zijn afgevinkt.

### Uitvoering v0.9 — verklaringen en transactionele migraties

Onder elke open F-ID staat een concrete `Reden:`-regel. De audit controleert
**destijds alle 186 uitlegvelden**, niet alleen vinkjes en symbolen. De
kennisdatabase beheert `PRAGMA user_version` expliciet: schema 0 naar 1 en
1 naar 2 gaan in afzonderlijke DDL-transacties, die bij fouten de oude
schemaversie behouden. Toekomstige schema's hoger dan 2 worden zonder
automatische downgrade geweigerd. De Python-runtimeprobe controleert de
PEP 668 `EXTERNALLY-MANAGED`-marker zonder systeeminstallaties uit te voeren.

Bewijs v0.9: **37 × 7 = 259 CLI-checks PASS**, **58 × 7 = 406
Python-helpers PASS**, **700 taalchecks PASS** en **29 Rust-tests PASS**.
De 260 producteisen blijven dezelfde; F223 werd IMPLEMENTED_TESTED,
F186 PARTIAL. Destijds: **74 geïmplementeerd en getest, 186 open**.

### Uitvoering v0.10 — begrensde PEP 610-packageherkomst

`deps` leest bij aangetroffen `.dist-info`-distributies optioneel
`direct_url.json` als onbetrouwbare metadata. Bestandsomvang maximaal 32 KiB,
symlinks weigeren, JSON-structuur valideren en uitsluitend geschoonde
URL-herkomstmetadata retourneren. VCS, archive en editable directory
worden onderscheiden. Herkomst blijft `RECORDED_NOT_VERIFIED`; dit is
geen controle van Git-commitintegriteit of PyPI-attestaties.

De end-to-end functiematrix toetst nu deze herkomstinspectie inclusief
geheimen in URL's onder alle zeven CPython-minorversies: **38 × 7 = 266
CLI-checks**, **62 × 7 = 434 Python-helpertests** en **700 taalcases** PASS.
De nieuwe F185/F202-subsets zijn PARTIAL. Checkliststatus:
**74 geïmplementeerd en getest, 186 open (16 PARTIAL)**.

### Uitvoering v0.11 — descriptorgebaseerde scan en lifecyclewaarschuwing

`scan` scheidt ontdekking van het analyseren van bestandsinhoud. Op Linux
opent de Rust-worker een ontdekt `.py`-bestand met `openat2` ten opzichte
van de projectroot (`BENEATH`, `NO_SYMLINKS`, `NO_MAGICLINKS`, `NO_XDEV`).
Alle hardlinks worden geweigerd. Vervolgens compileert de Python-helper
uitsluitend een begrensde onveranderlijke snapshot, nooit opnieuw het
originele projectpad. Het resultaat documenteert zijn beschermingsniveau.
Deze beveiliging is geen sandbox voor uitvoering van willekeurige code;
de discovery en de niet-Linuxvariant hebben nog resterende race-risico's.
Het afzonderlijke [veiligheidsmodel v0.11](SECURITY_MODEL_v0.11.md) beschrijft
de grenzen en negatieve controles.

De `runtime`-probe rapporteert de actuele CPython-supportfase voor alle
minorversies 3.9–3.15. Een onbekende toekomstige versie ontvangt
`UNKNOWN`, nooit een verzonnen supported-status. De data is herleidbaar
naar de Python Developer's Guide maar wordt niet automatisch synchroon
gehouden wanneer de upstream planning wijzigt; die uitbreiding blijft open.

Het releasebewijs v0.11 omvat **41 × 7 = 287 CLI-controles**,
**65 × 7 = 455 Python-helpertests**, **700 taalcases** en
**34 Rust-tests**. De checklist telt nu **75 IMPLEMENTED_TESTED**,
**17 PARTIAL** en **185 open** van de 260 geplande functies.

### Uitvoering v0.12 — conditionele updates, tombstones en herstel

De kennisupdater registreert welke officiële CPython-/PyPI-URL's actief
werden gecontroleerd. Als een eerder gevolgde bron wordt verwijderd,
verwijdert één SQLite-transactie de bijbehorende documenten en ETag en
bewaart een tombstone in het onderhoudsregister. Bij hernieuwde activatie
wordt de bron opnieuw opgehaald. HTTP 304 zonder eerdere ETag wordt
geweigerd; een beschadigde SHA256-cache forceert een volledige herdownload.

Bij commit schrijft de updater ook `committed_latest_stable`. Als het
vervangen van het externe JSON-versiemanifest daarna mislukt, verhindert
die transactieversie dat `--auto` een onterecht `SKIPPED_FRESH` geeft;
de volgende run kan de manifestwijziging alsnog afronden. SQLite-verbindingen
worden ook in uitzonderingspaden gesloten. F200 en F219 blijven PARTIAL:
historische niet-geregistreerde caches, realistische netwerkuitval en
OS-crashproeven zijn niet volledig afgedekt.

Nieuwe geteste stand: **70 × 7 = 490 Python-helpertests** plus de bestaande
**41 × 7 = 287 CLI-controles**, **700 taalcases** en **34 Rust-tests**.
De productchecklist heeft **75 IMPLEMENTED_TESTED, 19 PARTIAL en 185 open**.

### Uitvoering v0.13 — historische broncorrectie en snelheidsherhalingen

F219 controleert niet meer uitsluitend de nieuwste documenten per URI:
alle gearchiveerde updater-eigen versies worden met hun SHA256 gecontroleerd.
Een ongeldige oude rij wordt *pas na succesvol ophalen van de actuele bron*
verwijderd, binnen dezelfde SQLite-transactie als de nieuwe indexering.
ETags uit oudere updaterdatabases zonder `source_active`-registratie
kunnen nu alsnog als oude actieve bron worden gemigreerd en tombstoned.
Documenten die niet tot de updater-bronnaamruimte behoren blijven behouden.
Volledig herstel van nooit-geregistreerde bronnen en echte netwerkfoutscenario's
is nog niet bewezen; F219 blijft daarom PARTIAL.

F116 meet nu de SQLite-FTS5-laag met vijf **afzonderlijke** databases per
CPython-interpreter. Elke ronde bevat 10.000 synthetische documenten en 30
opgewarmde zoekmetingen; per ronde en cumulatief worden mediaan, p95,
opbouwtijd en vooraf vastgelegde 50 ms-p95-drempel bewaard. De versiegebonden
functiematrix behoudt elke meetronde als JSON-bewijs; hiermee is niet de
volledige Rust-herstelmotor gebenchmarkt. F116 en F115 blijven PARTIAL.

Uitvoering v0.13: **74 × 7 = 518 helpertests**, **42 × 7 = 294
functie-/benchmarkcontroles**, **700 taalcases**, **34 Rust-tests**.
Checklist: **75 afgevinkt, 20 PARTIAL, 185 open**.

### Uitvoering v0.14 — diagnoses vertrouwelijk, audit-observatie en kennisisolatie

- F207: de compile-only-helper geeft geen onbetrouwbare `str(exc)`-tekst door;
  `trace` onderdrukt standaard ruwe bronregels, padidentiteiten, functienamen
  en exceptionboodschappen. Padhashes laten frames correleren. Met
  `--show-sensitive` wordt uitsluitend op bewuste vraag detail getoond.
  Andere CLI-/omgevingsteksten zijn nog niet volledig geredigeerd.
- F210: `sys.addaudithook` registreert uitsluitend eventtellingen voor
  `open`/`compile`/`exec` tijdens de compile-only-probe. Noch auditargumenten
  noch broninhoud worden bewaard. Audithooks zijn **observatie, geen sandbox**.
- F208: kennisresultaten krijgen de expliciete data-only/trust-labels; de
  lokale catalogus behandelt kwaadaardige documentinstructies uitsluitend als
  indexeerbare bytes. AI-/tool-consumenten zijn daarmee nog niet bewezen veilig.
- F202: de catalogus weigert oversized/NUL-metadata en te lange FTS-vragen;
  een zipbomb- en parserfuzz-audit ontbreekt nog.

De functionele testmatrix wordt uitgebreid met nieuwe positieve en negatieve
fixtures op iedere echte CPython-minor 3.9–3.15. De huidige productchecklist
behoudt **75 afgevinkt en 185 open**: drie beveiligingsitems gaan van
`NOT_IMPLEMENTED` naar `PARTIAL` (**23 PARTIAL**) en vragen vervolgonderzoek.

### Uitvoering v0.15 — begrensde PEP 508-markers en extras

F058 krijgt een nieuwe offline AST-markerbeoordeling, geïsoleerd van
`exec`, `eval`, package-imports en pakketinstallaties. De evaluator behandelt
booleaanse combinaties, gelijkheid, in/uit, de bekende PEP 508-platformvelden,
finale numerieke Python-versies en de expliciet gekozen `--extra`-namen.
De originele `Requires-Dist`-waarden blijven intact; de afzonderlijke
markerstatus is driewaardig (`SATISFIED`/`UNSATISFIED`/`UNKNOWN`) of
`NOT_DECLARED`. De eigen versievergelijking is bewust slechts een subset van
PEP 440. Volledige transitive dependencyoplossing blijft uitgeschakeld.

Tests: zes nieuwe Python-negatief-/positiefgevallen per interpreter, één
nieuwe echte Rust-CLI-matrixcase per interpreter en één Rust-integratietest.
F058 blijft **PARTIAL**; lijststand **75 voltooid, 24 gedeeltelijk,
185 open**. Officiële specificatie:
https://packaging.python.org/en/latest/specifications/dependency-specifiers/

### Uitvoering v0.16 — PEP 440, projectmanifesten en wheelintegriteit

- **F057:** de Python-final-release-specifier ondersteunt `~=`, numerieke
  epochs, `===`, nulopgevulde releasevergelijkingen en maximaal 16 clausules.
  Onafhankelijke vergelijking van 378 finale voorbeelden met packaging 26.3
  gaf geen afwijkingen; niet-ondersteunde prereleases/ontwikkelversies blijven
  UNKNOWN en vormen geen volwaardige PEP 440-resolver.
- **F060:** het nieuwe read-only `project`-pad verzamelt SHA256/hashes en
  begrensde metadata van vaste rootmanifesten en lockfiles; alleen Python
  3.11+ krijgt complete `tomllib`-structuurparsing, 3.9–3.10 krijgt
  *PARTIAL* metadata-aanwijzingen. Importgraph en lockvalidatie zijn NOT_RUN.
- **F187:** een apart `record`-pad controleert lokale SHA256+grootte van
  gehanteerde `RECORD`-regels en weigert traversal, symlinks/hardlinks en
  overschreden quota. Dat levert geen provenance-/signature-proof of
  gegarandeerde anti-TOCTOU-isolatie op.

De twee nieuwe Rust-CLI-commando's zijn gescheiden van de bestaande
herstelpijplijn. Tests op elk van de zeven interpreters bevatten gerichte
positieve/negatieve fixtures. De huidige checklist heeft **75 afgevinkt,
27 PARTIAL en 185 open**; zonder sandbox of onafhankelijke behavioral
testoracle wordt geen definitieve zelfreparatie vrijgegeven.

### Uitvoering v0.17 — AST, metadata-SBOM, dependencygroepen en herhaaltests

- **F091/F097:** `ast` maakt zonder Python-bronuitvoering een begrensde CPython-
  AST-inventaris van functies, klassen, imports, bronposities en slechts
  mogelijke lokale aanroepen. Het valideert geen CST, control-flow of echte
  call-targets; `call_graph_verified=false` en `compile_proven=false`.
- **F183:** `project` telt extra-dependencies, dependencygroepen met geneste
  includes en build-vereisten onder de ingebouwde `tomllib` (3.11–3.15).
  Op 3.9–3.10 blijven deze gegevens `NOT_RUN`; een resolver of uitvoer van
  build-backends is niet geïmplementeerd.
- **F198:** `flaky` analyseert vooraf gemeten RETEST-evidence met strikte
  identiteit, herhaalbudget en expliciete conclusies `FLAKY`, `INCOMPLETE`
  en `REPEATABLE_PASS_NOT_VERIFIED`. Het voert geen projecttests uit.
- **F209:** `sbom` leest distributie-METADATA en afgeschermde URL-hashes,
  weigert grote/ongeldige metadata, en doet nadrukkelijk geen malware-/CVE-
  scan, dependencyresolutie of cryptografische publisherverificatie.

Alle vijf eisen gaan van NOT_IMPLEMENTED naar **PARTIAL**, dus **75
IMPLEMENTED_TESTED, 32 PARTIAL, 139 NOT_IMPLEMENTED, 7 NOT_RUN, 7
BLOCKED**. Elke van de **185** open functies behoudt een concrete reden;
geen gedeeltelijke functionaliteit krijgt ten onrechte een product-PASS.

### Uitvoering v0.18 — drie zelfstandig afgeronde criteria

- **F151 IMPLEMENTED_TESTED:** de Rust-CLI bevat een begrensde DAP-stdin/stdout-
  transportlaag met `Content-Length`-framing, een `initialize`-antwoord,
  capabilityonderhandeling via lege/false capabilities, `initialized`-event,
  weigering van `launch`/`evaluate`/dubbele `initialize` en expliciete
  `disconnect`/`terminated`-volgorde. DAP heeft volgens de officiële
  specificatie géén verplichte genummerde protocolversie; capabilities
  zijn de versie-onafhankelijke onderhandeling. Live debugging/DAP-client-
  conformantie blijft F152–F160/F241 open.
- **F180 IMPLEMENTED_TESTED:** een ingebedde, per echte CPython 3.9–3.15
  vastgelegde regressiecorpus met AST-syntax, bytecodeinstructies,
  exceptiontables en traceback-frames/notes. Onverwachte wijzigingen zijn
  `REGRESSION`, ontbrekende toekomstige referenties zijn `NOT_RUN`.
  Vaste vertrouwde fixtures, geen uitvoering van projectcode of pakket-API's.
- **F237 IMPLEMENTED_TESTED:** de aparte zesassige kwalificatiecontrole
  verplicht vooraf bepaalde harde PASS-grenzen, een code-/config-hashidentiteit
  en gedifferentieerd HMAC-geauthenticeerde rapporten vóór **iedere**
  beleidsranking. Zonder bewijs: `NO_WINNER`; maximaal één reserve. Dit
  bewijst niet dat een externe auditor daadwerkelijk correct testte,
  en er is geen release-autorisatie of onbekende code-uitvoering.
- **F240 PARTIAL:** deterministische beslislog en loghash aanwezig, maar
  duurzame immutable auditdatabase, cryptografische publisheridentiteit en
  veilige menselijke publicatieworkflow ontbreken.

De gekozen veiligheidsscope laat nu **78 IMPLEMENTED_TESTED, 33 PARTIAL,
135 NOT_IMPLEMENTED, 7 NOT_RUN, 7 BLOCKED** over. Alle **182** open
punten bewaren hun individuele reden. De inventariscontrole is verbeterd
zodat ook Rust-functies met generieke typeparameters niet buiten de telling
vallen. De uitvoering gebruikt twee werkelijk actieve specialistagents;
de 36 in dit document beschreven rollen blijven een ontwerp, geen 36
gelijktijdig uitgevoerde AI-processen.

### Uitvoering v0.19 — historisch bewijs van exact 100 afgevinkte functies

Rust `property` en `static` gebruiken uitsluitend ingebedde, vertrouwde
Python-helpers. `lab <adapter> --python <interpreter> -- <argumenten>`
ontsluit een allowlist van data-only adapters; elke Python-helper draait
geïsoleerd van sitepackages (`-I -S -B`) en met begrensde stdout/tijd.
Alle mutatie-/releasebevoegdheden voor onbekende projectcode blijven dicht.

- **Meten en prioriteren:** F040/F118–F121/F124/F194–F195/F231/F238
  omvatten reproduceerbare seeds, een geteste mutant, gerichte parser/CLI/
  updater-ingestie/FTS-fuzzing, OS-rusage van eigen vaste worker, echte
  gesimuleerde threadwachtrijen, append-only token-/kostmeting, 36
  rolprofielen, DAG en reporting per release. De router **start geen**
  externe AI-modellen en het meetinstrument **draait geen** projecttests.
- **Kennis en veiligheid:** F070/F078/F096/F212–F213/F217–F218/F227–F228
  gebruiken SQLite-versieedges, bron-URI/SHA, lokale HMAC-validatie,
  licentietoestemming/citatiequota, conflictreview en lokale append-only
  archiveringsregels. Externe publisherattestatie en fysiek WORM ontbreken.
- **Interpreter & audit:** F169/F175 vergelijken echte CPython-runtime-
  isolatie vanaf 3.14 en conservatieve ABI/wheel-tagcompatibiliteit (geen
  native module-uitvoering); F240 registreert geauthenticeerde zesassige
  beslislogs met controle van de hashketen. Onafhankelijke gedrags- en
  releasebewijzen blijven buiten scope.

**Nieuwe tests:** 542 × 7 echte Python-interpretaties = 3.794/3.794 PASS,
57/57 Rust-tests incl. Ruff, 84/84 offline Rust/CPython-labcases,
700/700 opnieuw uitgevoerde taal-/stdlibcases, Ruff `E4/E7/E9/F`, releasebuild
en strikte Clippy PASS. Een nieuwe 35-ronde FTS5-benchmark
in v0.19 heeft gecorrigeerde per-ronde p95 en globale p95 als harde gates.
Het opnieuw
uitvoeren van de volledige v0.19-netwerkgevoelige functiematrix is expliciet
**NOT_RUN**, niet achteraf als PASS ingevuld.

**Historische v0.19-checklist:** 100 IMPLEMENTED_TESTED, 38 PARTIAL, 108
NOT_IMPLEMENTED, 7 NOT_RUN en 7 BLOCKED. Elk van de **160 open** items
heeft een eigen reden. Geen van deze beperkte vinkjes is een volledige
productkwalificatie; sandbox, generieke gedragsequivalentie en binary-
self-update blijven onbewezen/uitgeschakeld.

### Uitvoering v0.20 — afgebakende, meetbare nieuwe paden

De centrale versiecontext blijft in Rust: `lab` is een expliciete lijst
ingebedde Python-helperprogramma's, uitgevoerd met een *gekozen werkelijk*
CPython-proces (`-I -S -B`), een maximale looptijd, uitvoerquotum en zonder
extra projectimports. De uitgebreide adapters zijn:

- `transitive-resolver`: backtracking en een afzonderlijke onafhankelijke
  uitputtende oracle, maar `UNKNOWN` voor versies buiten het geselecteerde
  PEP-440-final-releaseprofiel.
- `stdlib-api`: alleen statische `.py`-declaraties, per werkelijk Python-minor
  en SHA256 geëtiketteerd; C/native, runtime-decorators en dynamische imports
  worden niet geveinsd.
- `vector`: eigen SQL/FTS5/vector-index, expliciete partition keys
  `(python_minor, package, package_version)`, bron-URI en SHA256 als harde
  zoekfilters; geen embeddingmodel of ANN-kwalificatie.
- `backup-drill`: Rust migreert een vertrouwde bestaande kennisdatabase
  transactioneel vóór een expliciet gestarte lokale periodieke service;
  Python maakt WAL-consistente kopieën, herstelt ze in wegwerpdatabases en
  verifieert SHA256 + lokale hashketen. Een externe onveranderlijke ankerbron,
  OS-scheduler en externe recoverylocatie ontbreken.
- `reliability-bench` en `adaptive-jobs`: meting van herhaalde eigen vaste
  subprocessfixtures, vooraf vastgelegde p95/medianendrempels, uitsluitend
  begrensde eigen vertraagde subprocessjobs en live adaptieve slots.

Aanvullende Python-testmodules tonen conservatieve AST-dead-code- en
asyncio-diagnostiek, lokaal aangeleverde package-API-deprecations en
trustmetadata, bounded ZIP-inspectie, gehashte gescheiden agentwerkruimtes
en expliciet opt-in geredigeerde supportbundels. Reële willekeurige
projecttests, alle package-API's, code-sandboxing en volledig geauthenticeerde
bronupdates zijn hiermee **niet** bewezen. Het exacte aantal vinkjes en
alle individuele open redenen staan in `docs/FUNCTION_CHECKLIST.md`; eigen
bewijs per CPython-minor staat in `evidence/VALIDATION_v0.20.md`.

## Kritieke keten

1. **Discover**: interpreters, lockfile, dependencies, OS/ABI, tests, baseline.
2. **Analyze**: syntax/compile, Ruff, typecheck, importgrafiek, traceback.
3. **Retrieve**: relevante Python-documentatie, PEPs, package-API/changelog;
   bewaak herkomst, licentie, hash, Python-versie en packageversie.
4. **Propose**: onafhankelijk gegenereerde kandidaten in immutabele kopieën;
   registreer content- en configuratiehash **voor** tests.
5. **Verify**: geïsoleerde sandbox, expliciete resourcebudgetten, unit-,
   regressie-, property- en compatibiliteitstests; onafhankelijke audit.
6. **Rank & release**: alleen alle zes assen PASS; hoogstens één geverifieerde
   reserve. Bij algemene mislukking `NO_WINNER`, geen toepassing.

De Rust-CLI implementeert delen van 2, 3, 4, een **100-cases-per-versie
compatibiliteitsmatrix**, een parallelle projectscanner en de compilatie-
subcheck van 5. De Linux-releasebuild, Rust-integratietests, twee herstelpaden
en strikte lintcontrole zijn daadwerkelijk uitgevoerd. Volledige sandbox,
projectgedragsverificatie, multi-OS audit en productie-release blijven open.

Vanaf v0.5 horen hier bovendien twee **alleen-lezen** diagnosepaden bij:

- `trace`: deterministische ontleding van een opgeslagen traceback naar
  exceptiontype, laatste stackframe en adviserende vervolgstappen. De bron
  wordt niet opnieuw gestart. Geen gevalideerde causale debugging.
- `deps`: Python-stdlib `importlib.metadata` inventariseert distributies
  met `-I -S -B`, zonder de projectpackage te importeren of `.pth` uit te
  voeren. Een bewust beperkte PEP 440-subset (`>=`, `<`, `==` enz.) kan een
  enkele `Requires-Python`-regel vergelijken; complexe regels krijgen
  `UNKNOWN` en transitive compatibiliteit blijft `NOT_VERIFIED`.

### Versiegebonden end-to-end regressie (v0.5)

`tools/feature_matrix.py` voert **31 geautomatiseerde functiechecks per
CPython-interpreter** uit. Elke versie krijgt een eigen werkmap, eigen
databases en de gekozen interpreter wordt aan iedere relevante Rust-CLI-
aanroep doorgegeven. De controles omvatten alle huidige CLI-subcommando's,
positieve en negatieve paden, beide herstelroutes, variantcache/RETEST,
catalogus, updater-TTL, tracebackanalyse, dependency-metadata en de
volledige taaltestsuite. Binnen iedere versie
lopen daarnaast alle 40 Python-helpertests, inclusief een met HTTP-mocks
geteste officiële kennisupdate naar een hypothetische volgende minorrelease.

Werkelijk bewijs 2026-11-01: **217/217 functiechecks**, **280/280 helper-
testresultaten**, **700/700 unieke taal-/stdlibcases** PASS op CPython
3.9.25 t/m 3.15.0. De bevinding `SyntaxError('invalid syntax')` op 3.9
voor een ontbrekende dubbele punt is hierbij gerepareerd. Het volledige
machinale verslag met versie, testnaam, duur en foutstatus staat in
`evidence/FEATURE_MATRIX_v0.5.json`.

Het getal 31 is bewust het aantal testscenario's voor de **geïmplementeerde
CLI-oppervlakte**, geen claim over iedere interne codebranch, standaardlib-
API, externe packagefunctie, native ABI of netwerktoestand. Na een nieuw
versiemanifest plant de runner extra checks; ontbrekende interpreters
geven geen positieve uitslag. De echte continue `--watch`-loop en de
vervanging van Rust-binaries zijn geen gevalideerde updatefuncties.

## Python 3.9–actueel, inclusief toekomstige versies

- `config/versions.json` start met minimaal **3.9** en actueel stabiel
  **3.15.2** (vastgesteld op 2026-11-01 via Python.org).
- Python 3.9/3.10 blijven doelversies voor legacycode, ondanks EOL. Dat
  betekent geen beveiligingsondersteuning upstream.
- De matrix eist een **echte CPython-interpreter van precies de minorversie**.
  Bij afwezigheid: `NOT_RUN`; nieuwere parsers mogen niet doen alsof zij
  oudere interpreters volledig vervangen.
- Per versie **100 unieke tests**: 30 geldige syntax, 20 ongeldige syntax,
  20 feature-gates, 20 vertrouwde runtimecases en 10 standaardbibliotheekcases.
  Totaal 700 geplande gevallen in de huidige zeven-versiematrix.
- Voor iedere toekomstige stabiele 3.x-versie wordt de matrix automatisch
  met een rij en 100 geplande gevallen uitgebreid. Nieuwe syntaxiskenmerken
  vragen daarna aanvullende onafhankelijk geaudite tests; 100 bestaande
  cases garanderen geen volledige dekking.
- Huidig bewijs: alle zeven minors 3.9–3.15 daadwerkelijk getest:
  **700 PASS, 0 FAIL**, met CPython 3.9.25 / 3.10.22 / 3.11.17 /
  3.12.14 / 3.13.16 / 3.14.8 / 3.15.0. Volledige compatibiliteit met
  willekeurige packages en native extensies: **NOT_VERIFIED**.

## Zelfupdatebeleid

De update-engine ontdekt de actuele stabiele release via Python.org en
importeert officiële `docs.python.org/X.Y/whatsnew/X.Y.html` en geselecteerde
`pypi.org/pypi/<package>/json` metadata in SQLite FTS5.

1. Lees het huidige manifest en respecteer de 24-uurs TTL indien `--auto`.
2. Download alleen bekende HTTPS-hosts met begrensde omvang en verifieer
   response- en versiestructuur. Vergelijk ETag en hergebruik onveranderde
   documenten.
3. Maak versiegemarkeerde documenten; sla bron, datum en SHA256 op.
4. Werk de documenten in één SQL-transactie bij. Bij een ontbrekende bron
   wordt het bestaande versiemanifest niet vooruitgezet.
5. Verhoog het manifest atomair; de compatibiliteitsmatrix detecteert nu
   een nieuw stabiel minorversienummer en plant de volgende 100 tests.
6. Promoveer **geen** toekomstige Python-versie naar VERIFIED totdat alle
   interpreterchecks, project-/package-/ABI-tests en onafhankelijke audits
   slagen.

Live verificatie: Python.org meldde 3.15.2 en er zijn zeven officiële
versiedocumenten plus Ruff 0.17.3-metadata opgehaald. De daarna volgende
TTL-run gaf `SKIPPED_FRESH`. De update-engine kan zelf blijven draaien met
`--watch`, maar er is in deze sessie geen externe planner geïnstalleerd.

**Rust binary zelf updaten:** uitsluitend via een toekomstig ondertekend
releasekanaal met publisheridentiteit, SHA256, staged smoke tests, atomische
swap, rollback en expliciete releasebevoegdheid. Tot die tijd is binary
self-update **DISABLED**, terwijl de kenniscatalogus zichzelf wel kan
vernieuwen. No evidence = no release.

## Gegevensmodel en sync

**SQLite FTS5 `knowledge.sqlite`** is de snelle lokale bronlaag:

- `(source, uri, version)` uniek; bewaart `sha256`, titel, package,
  `python_constraint`, opgehaalde inhoud en tijdstip.
- FTS5 met BM25 voor letterlijke API-/symbolzoekopdrachten; triggers houden
  de index bij insert, update en delete synchroon.
- `import-installed` leest alleen distributiemetadata van de gekozen Python;
  het installeert geen packages en doorzoekt niet het internet.
- Een toekomstige synchronizer moet per bron `ETag`/versie, licentie,
  changelog, compatibiliteit en deprecations bewaren, en onbetrouwbare
  documentatie behandelen als data in plaats van instructies.

**SQLite `bench.sqlite`** bevat unieke varianten (code-SHA256, configuratie-SHA256,
engine-ID, parent) en alle evaluaties. Duplicaten worden vóór elke check
opgezocht; expliciete `--retest` voegt een nieuwe herhaling toe. Het huidige
logboek meet compilatieduur maar kan nog geen volledige benchmark bewijzen.

Later toe te voegen:

- **Qdrant** voor contextueel zoeken in lange documentatie; altijd filteren
  op productversie en geldige bronnen. Geen vectorindex voor exacte
  identifiers als FTS5 voldoende is.
- **DuckDB** voor offline regressieanalyse en vergelijkingen over historische
  benchmarksets, niet in het snelle write-path.
- Optioneel dependency-graaf in relationele tabellen; geen extra graph-DB
  tenzij echte queries dat rechtvaardigen.

## Onafhankelijke oplossingsvarianten

| Concept | Techniek | Status | Risico/voordeel |
|---|---|---|---|
| A: deterministisch | Ruff veilige fixes, daarna compile | **Gecompileerd; end-to-end PASS op gecontroleerde fixture** | Snel, beperkt oplossingsbereik |
| A2: syntax-heuristiek | Ontbrekende `:` alleen bij passende `SyntaxError`, opnieuw compileren | **Gecompileerd; end-to-end PASS op gecontroleerde fixture** | Smalle, apart geregistreerde herstelkandidaat |
| B: CST-behoud | LibCST-regels met Python-version API-constraints | Ontwerp, NOT_RUN | Behoud van comments/formattering, complexer |
| C: spec/test-gedreven | Minimal patch search + property/regressietests | Ontwerp, NOT_RUN | Groter bereik, meer CPU en sandboxrisico |

Per werkelijk gemaakte kandidaat wordt een runtime `V-<hash>` bewaard.
Geen fictieve resultaten, verzonnen agentruns of benchmarks. Het gekozen
`NO_WINNER` is een echte beleidsuitkomst zolang volledige tests ontbreken.

## Vooraf gedefinieerde toelatingscriteria

Alle zes assen zijn **harde toelatingseisen**; `NOT_RUN` is geen `PASS`.

| As | PASS-drempel voor toekomstig volledig systeem | Huidige bewijsstatus |
|---|---|---|
| VEILIGHEID | Geen hostschrijf-/netwerktoegang vanuit tests; sandboxgrenzen en dependency supply chain onafhankelijk geaudit; geen kritieke bevindingen | NOT_RUN |
| CORRECTHEID | Compile + bestaande regressietests + relevante gegenereerde tests 100% geslaagd; geen verloren gedrag binnen testoracle | NOT_RUN; compile-subcheck beschikbaar |
| SNELHEID | Zelfde fixture, >=5 runs, mediane totale verwerking <= afgesproken baseline en p95 <= 2× mediaan | NOT_RUN; één compileduurwaarde in log |
| BETROUWBAARHEID | >=10 identieke herhalingen zonder crash, verschil of timeout | NOT_RUN |
| COMPATIBILITEIT | Matrix voor project-Python, ondersteunde OS/ABI en gelockte dependencies volledig groen | NOT_RUN |
| TOEKOMSTBESTENDIGHEID | Versie-/deprecation-regressies, bronvernieuwing en migratietests groen | NOT_RUN |

Het voorgestelde FTS5-microbenchdoel is p95 zoeklatentie <= 50 ms bij 10.000
lokale documenten; dit is een aparte databasecheck en **geen** claim over
end-to-end herstelsnelheid. Bij limieten/budgetoverschrijding wordt werk
gestopt. Ranks mogen pas berekend worden na volledige onafhankelijke audit.

## 36 gespecialiseerde rollen en adaptieve uitvoering

Dit is een **rollenplan**, geen 36 gelijktijdige AI-processen. Op dit moment
zijn **0 gedelegeerde agents actief** en er is geen onafhankelijke agentaudit.
Een toekomstige scheduler zou maximaal beschikbare veilige paralleliteit
gebruiken, met geïsoleerde werkmappen per kandidaat, afhankelijkheden en
kritiekpad als leidraad en procesbezetting als aparte meetwaarde.

| Cluster | Rollen |
|---|---|
| Regie | 01 Orchestrator; 02 Requirements; 03 Threat modeling; 04 Budget; 05 Resource planning; 06 Releasebeheer |
| Diagnose | 07 Python-grammatica; 08 Stdlib; 09 Typeanalyse; 10 Imports/dependencies; 11 Traceback; 12 Testanalyse |
| Herstel | 13 Ruff-fixes; 14 CST-transformaties; 15 AST-strategie; 16 API-migratie; 17 Packaging; 18 Conflictresolutie |
| Kennis | 19 Python-documentatie; 20 PEP-tracking; 21 PyPI-metadata; 22 Package-docs; 23 Changelogs; 24 Bronherkomst |
| Data | 25 FTS-index; 26 Vectors; 27 Dependency-graph; 28 Hashregister; 29 Sync/cache; 30 Backup/audittrail |
| QA | 31 Correctheid; 32 Sandbox/security; 33 Latency; 34 Reproduceerbaarheid; 35 Compatibiliteit; 36 Futureproofing |

**Adaptief beleid:** begin met één coördinator en alleen onafhankelijke
read-only checks parallel; schakel pas kandidaatwerkers in na bron-snapshot
en budgetautorisatie. Monitor queue delay, wall time, CPU/RAM, fouten,
herhalingsratio en model-/compute-kosten per variant. Schaal af bij
regressie, quota of dalende marginale doorvoer. Claims over agentprocessen,
kostenbesparing of snelheidswinst zijn momenteel **NOT_RUN**.

## Volgende iteraties

1. Huidige succesvolle Rust-/Python-/Ruff-builds uitbreiden met meerdere
   OS- en CPython-runners en onafhankelijke reproduceerbare audits.
2. Projectdetectie uitbreiden met lockfiles via `uv`, exacte Python-interpreter
   en gebruik project-specifieke Ruff-regels in een veilige staging-map.
3. Echte container/VM-sandbox, netwerk uit, schrijfbare alleen-tijdelijke
   workspace, CPU/RAM/timeouts en testcommandowhitelist.
4. Onafhankelijke varianten B en C bouwen, corpus uitbreiden en benchmarken.
5. Bestaande officiële docs-/PyPI-sync uitbreiden met Python-referentie,
   PEPs, package-docs en changelogs, inclusief licentiebeheer en provenance.
6. Transactiegewijze patchselectie, approval gate, rollback en CI-integratie.
