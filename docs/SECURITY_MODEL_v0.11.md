# Veiligheidsmodel v0.11: gesnapshotte projectscan (Linux)

Peildatum 2026-11-01. Dit document bouwt voort op [v0.8](SECURITY_MODEL_v0.8.md).
De scanner is nog geen container of VM-sandbox. Onbekende Python-broncode
wordt enkel **gecompileerd**, nooit geïmporteerd of uitgevoerd.

## Ingevoerde mitigatie (F105/F203)

1. De Rust-discovery slaat symlinks en uitgesloten mappen over.
2. Bij elke `.py` wordt op Linux een descriptor ten opzichte van de
   projectroot geopend via `openat2`, met `RESOLVE_BENEATH`,
   `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_MAGICLINKS` en `RESOLVE_NO_XDEV`.
3. De bronhandle moet een regulier bestand zijn met precies één hardlink.
   Alle hardlinks worden conservatief geweigerd: anders zou een hardlink in
   de projectmap naar een doel buiten de projectmap kunnen wijzen.
4. De inhoud wordt maximaal 4 MB naar een eenmalige snapshot gelezen.
   De geselecteerde originele bestandsnaam wordt vervolgens niet meer aan
   Python doorgegeven; Python compileert alleen de snapshot.
5. Een mislukte veilige opening wordt als `NOT_RUN` gerapporteerd. Een scan
   met niet-geverifieerde bestanden krijgt geen valse `PASS`.

De JSON-uitvoer vermeldt op Linux
`path_protection=OPENAT2_NO_SYMLINKS_BENEATH_NO_XDEV_AND_HARDLINK_REFUSAL`.
Op andere platformen meldt ze `BEST_EFFORT_NO_TOCTOU_GUARANTEE`.

## Geteste aanvalsklassen

- Externe directorysymlink wordt overgeslagen bij discovery.
- Externe bestandssymlink wordt bij discovery en descriptoropening geweigerd.
- Traversal via `..` wordt geweigerd.
- Hardlinks, inclusief naar externe bestanden, worden geweigerd.
- Normale bestanden worden via een snapshot gecompileerd zonder side-effects.
- Een scan met een hardlink meldt `INCOMPLETE`, nooit ongefundeerd succes.

Rust-unit- en integratietests plus de 7-versies-end-to-endmatrix leggen dit vast;
zie `evidence/VALIDATION_v0.11.md`.

## Resterende risico's (NIET gevalideerd)

- De initiële discovery gebruikt nog bestandsnamen en `read_dir`, niet overal
  descriptorgebonden directory-traversal. Concurrente rootvervanging is
  niet onafhankelijk met races/fuzzing aangetoond.
- De niet-Linuxfallback is niet `openat2`-equivalent en is niet op macOS of
  Windows getest; F105 blijft daarom PARTIAL.
- Hardlinks binnen de projectmap worden ook geblokkeerd: veilige maar
  mogelijk onnodig beperkende false positives.
- Linux kernelversies zonder `openat2` geven `NOT_RUN`; er is geen stille
  terugval naar zwakkere beveiliging op Linux.
- Een snapshot is geen sandbox voor **uitvoering** van projectcode: Python
  subprocessuitvoering van onbekende code blijft uitgeschakeld. F039,
  F107, F108 en F204–F206 blijven geblokkeerd.
- Volledige onafhankelijke veiligheidstoets, strestests en fuzzing ontbreken.

Bron voor de gebruikte Linux-pathresolutie:
[openat2(2), Linux man-pages](https://man7.org/linux/man-pages/man2/openat2.2.html).
