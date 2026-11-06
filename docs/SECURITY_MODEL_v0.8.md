# Veiligheidsmodel Rust Python Healer v0.8

Dit document beschrijft de grenzen van de **huidige** ontwikkelversie,
geen onafhankelijke beveiligingsaudit. De bedreigingen gelden voor Python
3.9–3.15 én toekomstige versies, omdat ook toekomstige documenten, packages
en code onbetrouwbaar kunnen zijn.

## Vertrouwensgrenzen

| Invoer/actor | Dreiging | Nu geïmplementeerde controle | Open eis |
|---|---|---|---|
| Onbekende Python-projecten | Code-uitvoering, bestandstoegang, netwerk, procesuitbraak | `check`/`scan` compileren zonder doelcode uit te voeren; subprocess-timeout en outputgrens | F039, F107–F109, F204–F206 |
| Projectpad/symlink | Traversal, TOCTOU, externe projectbestanden | Symlinks worden bij scan-ontdekking overgeslagen; root-symlink geweigerd | F105, F203: nog geen sterke descriptor- of mountisolatie |
| Python-package en `.pth` | Supply-chain-code en kwetsbare dependencies | Metadata-inspectie laadt geen projectmodule of `.pth` | F057–F060, F185–F190, F209 |
| Remote docs/PEPs/PyPI | Prompt injection, bronvervalsing, zipbom | HTTPS-allowlist, domeincontrole, antwoordlimieten, SHA256 op inhoud | F070, F202, F208, F211–F219 |
| Lokale gebruikerslogs | Tokens, paden, PII, broncodelek | Begrensde helperoutput; **geen algemene redactie** | F207, F249 |
| SQLite-kennisdatabase | Misleidende/corrupte index, WAL-verlies | FTS5 extern-content-integrity, rebuild, optimize, WAL-consistente snapshot | F221–F223, F229 |
| Back-upvervanging | Ongecontroleerd herstel of bestandsoverschrijving | SHA256 verplicht, integriteitscontrole, nieuwe bestemmingsfile, weigering bestaande doelen | F080, F224: nog geen getekende attestatie, planning of calamiteitenprocedure |
| Rust-binary-update | Uitvoerbaar bestand vervangen door aanvaller | Binary-self-update uitgeschakeld | F090, F148–F150 |
| Live IDE/debugger | Autorisatie, expressie-uitvoering, secrets | Geen live DAP of remote-attach actief | F151–F160, F241–F244 |

## Harde blokkeringen

1. **Geen onbekende projecttests automatisch uitvoeren.** `-I -S -B`,
   compileren en Python-audithooks vormen *geen* OS-sandbox.
2. Geen reparatie toepassen zonder verifieerbare projectregressie,
   veiligheidstoets, compatibiliteit en expliciete releasebevoegdheid.
3. Geen signed-updateclaim op basis van alleen HTTPS of SHA256.
4. Geen opgewaardeerde checkliststatus wanneer slechts mocks zijn getest
   maar free-threaded, PyPy, native ABI, Windows/macOS of toekomstig Python
   in werkelijkheid ontbreekt.
5. Bij onbekende uitkomst `NOT_RUN`, bij onveilige uitvoer `BLOCKED`, en bij
   onvoldoende zes-assig bewijs `NO_WINNER`.

## Verificatieroute

- Bestaande en nieuwe positieve/negatieve lokale fixtures staan in `tests/`.
- Onder elke aanwezige CPython-minor draait `tools/feature_matrix.py`.
- Afzonderlijke OS-/containerisolatie- en supply-chainreview is verplicht
  voordat onbekende code actief mag worden uitgevoerd.
- Een veiligheidsmodel bevat aannames en testgevallen, maar **is zelf
  geen onafhankelijke audit of bewijs van een sterke sandbox**.

Bronnen: [Python auditing hooks](https://docs.python.org/3/library/sys.html),
[SQLite FTS5 integrity-check](https://www.sqlite.org/fts5.html),
[SQLite VACUUM INTO](https://www.sqlite.org/lang_vacuum.html).
