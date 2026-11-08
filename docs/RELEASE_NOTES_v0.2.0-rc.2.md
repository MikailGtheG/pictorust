# PictoRust v0.2.0-rc.2 — technische Vorschau

> **We trust in PictoRust!**
>
> Das PictoChat-Gefühl von damals. Mit Verschlüsselung für heute.

**Status:** Release-Candidate-Unterlagen; ein öffentlicher Release ist
hiermit **nicht** bereits veröffentlicht oder als unabhängig
sicherheitsgeprüft freigegeben.

## Highlights

- Die originale Nintendo-DS-/PictoChat-Oberfläche mit zwei Bildschirmen,
  50 originalen Tastatur-Hitboxen und Räumen A–E bleibt erhalten.
- Der standardmäßige Browserchat verwendet **OpenMLS in WebAssembly** für
  Ende-zu-Ende-verschlüsselte Nachrichten und Zeichnungen.
- Einladung per bestehendem Button und Link; neue Mitglieder erhalten
  eigene Zugangstokens und kryptografisch verifizierte Welcome-Nachrichten.
- Individuelle Relay-Token können bei Ausschluss widerrufen werden.
- Begrenzter sicherer Wiederbeitritt nach einem einzelnen
  Verbindungsabbruch durch neues MLS-Welcome und neue Mitgliedschaft.
- Rust-Relay mit HTTPS/WSS-Konfiguration via Caddy, strenger Herkunftsprüfung
  und lokalen systemd-Sicherheitsbeschränkungen.
- Multilinguale Zeichen und originalgetreue pixelbasierte A4-PDF-Exporte.
- Chromium-Mehrbrowser-Tests für Text, Zeichnungen, Gruppenoperationen,
  Originaldesign, HTTPS/WSS und den begrenzten Wiederbeitritt.

## Grenzen und bekannte Einschränkungen

Diese Version ist **kein abschließend geprüfter privater Messenger**.
MLS-Zustände werden nicht sicher und dauerhaft über einen Browserneustart
gespeichert. Lange Offline-Phasen, verpasste MLS-Commits, ein ausgefallener
Gruppeninhaber und ein Serverneustart benötigen weiterhin eine neue
Einladung bzw. eine weitergehende Recovery-Architektur. Ein Einladungslink
beweist nicht automatisch die echte Identität des Absenders.

Der öffentliche Internetbetrieb ist konfiguriert, wurde aber nicht auf
einem öffentlich erreichbaren Produktivserver nachgewiesen. Die Tests
prüfen localhost und einen temporären HTTPS/WSS-Proxy.

Ein unabhängiger Security-Review, Rechte-Dokumentation und manuelle
Abnahmetests auf realen Geräten stehen noch aus.

## Installation und Verifikation

Siehe [README](../README.md),
[Deployment](../deploy/README.md) und
[Release-Gates](RELEASE_CANDIDATE.md). Vor einem Tag oder einer
Veröffentlichung muss der konkrete Merge-Commit auf allen sechs
GitHub-Actions-Workflows erfolgreich gewesen sein.

## Danksagung und Ursprung

Die Idee zu PictoRust kam nach einem Hinweis von Alperen auf picto.app
und einem anschließenden technischen Review zustande. Die Projektgeschichte
steht in der [README](../README.md). Der originale Quellcode und die
Bildmaterialien werden in [CREDITS](../CREDITS.md) gewürdigt.

**We trust in PictoRust!**
