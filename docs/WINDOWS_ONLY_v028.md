> Historische v0.28-voorbereidingsregistratie. Actuele ontwikkelstand:233/260,
> met F253/F254-bewijs in `evidence/windows_v029/` en de beperkte lokale
> Windows-build-/runtimekwalificatie F145 in `evidence/windows_r6/CORE_VALIDATION.json`.
> Deze oudere NOT_RUN-velden zijn geen actuele uitvoerstatus; zie de centrale checklist.

# Rust Python Healer — Windows 11 Home x64/NVIDIA patchkit v0.28

**Type:** volledige v0.27-bronboom plus geïntegreerde Windows v0.28-patch,
**ontwikkelkandidaat, geen Windows- of productierelease**. De gebruiker heeft
de complete oorspronkelijke v0.27-ZIP opnieuw geleverd. Het centrale
260-functieregister en de Rust-broncode zijn teruggezet en opnieuw geaudit:
**230 IMPLEMENTED_TESTED, 16 PARTIAL, 7 NOT_RUN, 7 BLOCKED**.
De 30 open functies zijn dus niet stilzwijgend goedgekeurd.

## Beoogd systeem

- Windows 11 **Home**, Intel/AMD x64, **NVIDIA**.
- Geautomatiseerde GitHub-hosted Windows x64-runner voor CPython3.9–3.15.
- De label `windows-2025` gebruikt **Windows Server 2025, niet Windows 11
  Home**. De CI kwalificeert Windows x64-programmeerbaarheid, niet de exacte
  Home-editie. Hiervoor is later een echte Windows 11 Home-host of equivalent
  onafhankelijk beheerde testomgeving nodig; het veld
  `exact_windows_11_home_host_verified` blijft op hosted Server false.
- macOS F177 is `OUT_OF_SCOPE_NOT_A_PASS`, nooit `IMPLEMENTED_TESTED`.
- Windows Sandbox is geen oplossing op Home. Geïsoleerde hosted CI kan
  vaste, vertrouwde fixtures uitvoeren; voor **willekeurige onbetrouwbare
  Python-projecten** is afzonderlijke en aantoonbare VM-/sandboxbeveiliging
  vereist. Een GitHub-runner is niet automatisch bewijs van volledige isolatie.
- Een standaard hosted Windows-runner is **geen bewezen NVIDIA CUDA-runner**.
  GPU/CUDA en echte PyTorch/TensorFlow/JAX-suites blijven `NOT_RUN` totdat
  er een expliciete GPU-runner met gecontroleerde dependencies beschikbaar is.

## Inhoud

| Bestand | Functie | Wat het niet bewijst |
|---|---|---|
| `windows_qa/src/lib.rs` | Begrensde, fail-closed Rust PE32+/x64-headerinspectie + negatieve unitfixtures | Geen Authenticode, Windows procesrun, hashes of updater |
| `windows_qa/Cargo.toml` | Apart dependencyvrij Rust-component | Geen compile/test zonder Rust-toolchain |
| `windows_qa/windows_runtime.py` | Echte Windows-host- en CPython-minorcontrole + vertrouwde child-PID fixture | Geen arbitraire code-uitvoering, isolatie of GPU |
| `windows_qa/windows_scope.json` | Geherauditeerde mapping van 30 open F-ID's met `NO EVIDENCE = NO PASS` | Geen Windows-PASS voor die punten |
| `windows_qa/qualify_curated.py` | Echte afzonderlijke 100-case Python-suite met identiteit-, duplicaat- en SHA-controles | Geen ongeteste Python-minors of externe package-API-dekking |
| `windows_qa/tests/` | Versie-, trust-, updater-stop-, scope- en CI-contracttests | Statisch/gesimuleerd bewijs ≠ Windows-uitvoering |
| `python/binary_self_update_v27.py` | Import op Windows mogelijk; Linux-only ELF/`flock`-mutatie expliciet geweigerd vóór I/O | Windows PE64-update/rollback nog **niet** gebouwd |
| `.github/workflows/windows-native-matrix.yml` | Windows Server 2025 x64 runner × Python3.9–3.15, 100-case suites, Rust- en Python-tests, JSON-artifacts | Geen uitgevoerde GitHub Actions-runs |

## Huidige validatie

- `python3 -I -B -m unittest discover -s windows_qa/tests -p 'test_*.py' -q`:
  **39/39 PASS op de aanwezige Linux CPython 3.12**.
- `python3 -I -B -m unittest discover -s tests -p 'test_*_v27.py' -q`:
  **221 tests: 188 geslaagd, 33 overgeslagen**, geen failures. Die skip zijn
  geen PASS en dezelfde suites moeten op Windows opnieuw draaien.
- `python3 -I -S -B python/version_suite.py`: **100/100** geselecteerde
  taal-/stdlibgevallen op echte **Linux CPython 3.12.14**.
- Windows-CI bevat **7 minors**, waarvan voor elke minor de exact 100
  geselecteerde lokale Python-checks afzonderlijk worden opgeslagen.
- Geïntegreerde 260-item checklist-audit: **PASS**, 30 open met redenen;
  bronregister opnieuw gegenereerd; niet gelijk aan 260 Windows-PASS.
- Brede historische regressiesuite op diezelfde Linux-interpreter:
  **2034 tests gedetecteerd, 48 failures, 17 errors, 64 skips**. Deze
  **overall FAIL** is niet weggelaten: er ontbreken onder meer een echt
  herbouwde Rust-release, Ruff en gepinde typechecker-/CST-wheels. De
  geïsoleerde Python-importomgeving verhinderde ook enkele bestaande
  `python.*`-imports. Geen volledige testsuite-PASS.
- Opnieuw met de normale Python-importmodus zijn **2.141 tests ontdekt**:
  **48 failures, 12 errors, 64 skips**. Het aantal importfouten daalde,
  maar de volledige suite blijft terecht **FAIL** door ontbrekende
  oorspronkelijke binaries, testbundels en verplichte tools.
- SQLite FTS5-benchmark: **5 onafhankelijke runs**, 10.000 records,
  150 querymetingen, **p95 = 4,4293 ms** versus vooraf vastgelegde
  p95-grens 50 ms. Alleen Linux/SQLite FTS5, niet de Windows-Healer-pipeline.
- De Rust-toolchain en zes eerdere CPython-minors zijn door workspace-opschoning
  verwijderd. **Rust-testuitvoering = NOT_RUN; Python3.9,3.10,3.11,3.13,
  3.14,3.15 = NOT_RUN; echte Windows = NOT_RUN**.
- Geen onafhankelijk externe beveiligingsaudit, geen Windows-binary,
  geen GPU-framework-run, geen geautoriseerde release.

## Nog uit te voeren Windows-kwalificatie

1. Verifieer de geïntegreerde Rust-hoofdbinary en PE-parser met
   `cargo test --manifest-path windows_qa/Cargo.toml --offline`.
2. Start **via een geautoriseerde GitHub-repository** de Windows-workflow.
   Deze voert de echte root-Rust-tests, Windows-compile én zeven Python-
   suites én zeven onafhankelijke 100-case-taalsuites uit. Iedere rode/
   ontbrekende cel blijft `FAIL`/`NOT_RUN`.
3. Herontwerp F090 voor PE64/Authenticode, Windows-bestandslocks, proces-
   vervanging en rollback; de Linux ELF/flock-updater is niet Windows-compatibel.
4. Test DAP/LSP in echte IDE-hosts. Gebruik voor NVIDIA een expliciet
   geautoriseerde GPU-runner met werkelijk geïnstalleerde frameworks.
5. Voeg per F-ID resultaat, tests, artifact-/codehash en alle zes kwaliteits-
   poorten toe aan de oorspronkelijke checklist. Markeer geen `PASS` op
   basis van uitsluitend statische of gesimuleerde tests.

**Status:** geïntegreerde bronboom, lokaal geteste Windows-voorbereiding;
daadwerkelijke Windows-kwalificatie en productie-integratie blijven open.
