# PictoRust

**PictoRust** is the new name for the ongoing Rust and TypeScript modernization of the original Nintendo DS PictoChat browser implementation.

> **Original creator credit:** This project is derived from [ayunami2000/ayunpictojava](https://github.com/ayunami2000/ayunpictojava). The original Java/browser work, DS sprites and bundled font are retained with attribution. See [CREDITS.md](CREDITS.md) for rights and provenance; this fork is independent and unaffiliated with Nintendo.

<p align="center"><strong>We trust in PictoRust!</strong></p>

<p align="center"><em>Das PictoChat-Gefühl von damals. Mit Verschlüsselung für heute.</em></p>

## Wie alles begann

Die Idee zu **PictoRust** begann nicht mit einem Businessplan, sondern mit
einem Link von **Alperen**. Er zeigte mir **picto.app** – und sofort war
dieses Nintendo-DS-PictoChat-Gefühl wieder da: kleine Räume, Zeichnungen
und ein Chat, der einfach Spaß macht.

Aus Neugier wurde ein technischer Code-Review. Dabei stellten wir uns Fragen
gestellt, die wir bei einem privaten Messenger unbedingt beantwortet haben
wollten: **Wer kann Nachrichten mitlesen? Wo endet die Verschlüsselung?
Welche Informationen verarbeitet der Server?** Die vorgefundene
Java-basierte Architektur und die aus unserer Sicht nicht ausreichend
nachvollziehbaren Datenschutz- und Verschlüsselungsgarantien waren der
Ausgangspunkt unserer Diskussion. Gerade die Möglichkeit, dass ein Server
Chats mitlesen könnte, wollten wir für *unser eigenes Projekt* technisch
ausschließen.

**Wichtig:** Das beschreibt unsere damaligen Bedenken und Motivation –
keine nachgewiesene Behauptung, dass picto.app tatsächlich Gespräche
überwacht oder Daten missbraucht. Eine Code-Betrachtung allein kann das
Betreiberverhalten nicht beweisen.

Statt nur über die Probleme zu reden, wollten wir zeigen, wie man das
vertraute PictoChat-Erlebnis mit modernen Mitteln neu umsetzen kann:
mit einem **Rust-Server**, **OpenMLS-basierter Ende-zu-Ende-Verschlüsselung**,
sicheren Gruppeneinladungen, originalgetreuer Nintendo-DS-Bedienung und
möglichst wenig unnötiger Datenspeicherung.

So entstand **PictoRust**.

> **We trust in PictoRust!** – Nicht, weil man einem Server blind
> vertrauen soll, sondern weil Privatsphäre überprüfbare Technik braucht.

## Projektziele

- **Originalgefühl bewahren:** Zwei DS-Bildschirme, A–E-Räume, Tastatur,
  Zeichnungen und pixelgetreue PDF-Exporte behalten ihre Form.
- **Privatsphäre technisch umsetzen:** OpenMLS verschlüsselt Nachrichten
  auf den Endgeräten. Der Rust-Relay kann deren Inhalt nicht entschlüsseln.
- **Einfach statt kompliziert:** Raum öffnen, Link teilen, chatten –
  ohne sichtbare Kryptografie-Menüs.
- **Offen nachvollziehbar:** Code, Tests, bekannte Einschränkungen und
  Herkunft der ursprünglichen Arbeit bleiben dokumentiert.
- **Keine falschen Versprechen:** Dieses Projekt ist noch kein unabhängig
  auditierter, fertig abgesicherter Messenger.

## Aktueller Release-Stand

**PictoRust v0.2.0 RC – technische Vorschau.** Die originale UI mit
OpenMLS, Einladungslinks, Zeichnungen, PDF und einem begrenzten sicheren
Wiederbeitritt funktioniert in automatisierten Mehrbrowser-Tests über
localhost sowie HTTPS/WSS. Der Rust-Relay wird hinter einem TLS-Proxy
weiterhin nur an `127.0.0.1` gebunden.

**Nicht als produktionssicher freigegeben:** Es fehlen unter anderem
dauerhafte sichere MLS-Zustandswiederherstellung nach einem Browserneustart,
Offline-Synchronisierung über verpasste Gruppen-Epochen, umfassende
Identitätsprüfung und ein unabhängiges Security-Audit.

Die Projektverantwortlichen geben an, dass eine Erlaubnis zur Nutzung
der benötigten Materialien vorliegt. Der genaue Umfang dieser Erlaubnis
(Code, Grafiken, Schriftarten, Verteilung und Änderungen) muss vor einer
öffentlichen Veröffentlichung mit der jeweiligen Rechtekette
abgeglichen und dokumentiert werden; die Herkunft bleibt in
[CREDITS.md](CREDITS.md) erhalten.

Siehe [Release-Gates](docs/RELEASE_CANDIDATE.md),
[Deployment](deploy/README.md) und
[echte Chromium-/MLS-Integrationstests](.github/workflows/pictorust-browser-mls.yml).

## OpenMLS in the original Nintendo DS interface

Open `http://127.0.0.1:8787/` after building the WASM client. **The
original `server/public/index.html` and every Nintendo DS sprite, keyboard
hitbox, chat frame and print renderer are unchanged.** The default client
on that page now uses the Rust OpenMLS WebAssembly adapter, and existing
room/create/connect/invite/send controls. No MLS-specific UI was added.
A local visual regression mode retains the prior experimental v2 transport
under `/?legacy=1`; the public HTTPS server rejects v2 frames entirely.

A room owner selects A–E, creates a temporary room and copies the existing
invite link. The link contains a random invitation secret and creator key
in the URL **fragment** (never the HTTP path); a guest opens it, automatically
gets a verified OpenMLS Welcome and an individual relay bearer, and uses the
same original chat interface. Owner-only authenticated group changes and
per-device relay revocation are enforced in the Rust/WASM clients and relay.

**Limited connection recovery:** One transient guest disconnect can
automatically renew membership while the owner is online. The guest proves
its previous individual relay bearer, the owner removes the previous MLS
member and revokes its token, then creates a fresh cryptographic Welcome.
This is not durable session recovery across reloads, server restarts or long
offline periods.

The [browser MLS integration workflow](.github/workflows/pictorust-browser-mls.yml)
verifies a three-peer group, original DS keyboard/drawings/PDF and the
live two-browser invite/recovery path, over both localhost HTTP and a
real HTTPS/WSS test proxy. The [operational deployment guide](deploy/README.md)
documents Caddy TLS termination, exact allowed Origin, a restricted systemd
service and the remaining release blockers.

For local testing on Linux with Rust, wasm-pack and OpenSSL:

```sh
bash scripts/build-local-mls.sh
PICTOCHAT_RELAY_SECRET="$(openssl rand -hex 32)" \
  ./build/pictorust-mls-local/run.sh
curl --fail http://127.0.0.1:8787/mls/healthz
```

The original interface is at `/`; the separate `/mls` page is now only an
engineering diagnostic view. `GET /mls/healthz` returns HTTP 503 until
the required real WASM/JS files are present.

**Not production security/a public release:** Invitation links are bearer
capabilities and must be delivered through trusted channels. No persistent
encrypted MLS device-state backup, offline missed-Commit catch-up, owner
recovery, independently reviewed identity directory, independent security
assessment or proven third-party asset distribution permission exists yet.
A successful CI build does not substitute for those requirements.

## Visual verification

The screenshot and PDF integration workflow renders a real two-peer browser session with the original DS assets, Unicode and drawings, then checks print pagination at A4 dimensions. Its review artifacts contain:

- `pictochat-original-lobby.png` – original room selection with updated session controls.
- `pictochat-original-top-messages.png` – framed text, drawing and bilingual chat in the top DS screen.
- `pictochat-original-stage.png` – full original two-screen layout.
- `pictochat-original-draft-box.png` – pen/drawing field and original frame.
- `pictochat-mobile.png` – narrow-screen viewport verification.
- `pictorust-export-page-1.png` – high-resolution nearest-neighbor source raster.
- `pictochat-print-preview.png` – actual Chromium PDF page rendered to PNG.
- `pictochat-print-demo.pdf`, `pictorust-multipage-demo.pdf` – downloadable print proofs.

**View the latest real screenshots and print proof:** [Browser & PDF workflow](https://github.com/MikailGtheG/pictorust/actions/workflows/pictochat-browser-screenshots.yml).
The workflow produces new review artifacts on each tested update; do not substitute mockups for test screenshots.

The modern client is in `frontend/`, the volatile Rust relay is in `server/`, and the independent OpenMLS security laboratory is in `mls-lab/`. The graphical interface reuses the original fork's PictoChat sprites and pixel font.

**PictoRust PDF export:** renders a continuous original-width Nintendo DS sprite chat strip, without resetting the conversation at each 192-pixel screen. Each 256×520 logical raster is rendered from integer-aligned glyph bitmaps and pre-upscaled 4× into a 1024×2080 PNG, then printed at 512×1040 CSS pixels and centered on an A4 portrait page. Message frames stay intact across page boundaries. Original nds.ttf font and sprite backgrounds are used; no headers, footers, explanatory notes, access tokens or document-style cards. Browser export is client-only. The local browser holds the history only for the active session.

This development branch uses OpenMLS in the original browser interface. Public deployment still requires independent security review and reliable persistent MLS recovery. The original Java instructions below remain for historical compatibility.

## Original fork / legacy Java documentation

Pictochat for the Nintendo DS & DSi, recreated for browsers!

# NOTICE: this project does NOT endorse nor is associated with ANY crypto or NFT projects

don't get scammed kthx

## In-app commands
- `!block` / `!ignore` / `!unblock` / `!unignore` - Hide/unhide the messages of someone temporarily.
- `!tripcode` / `!tc` - When provided with a password, will generate a tripcode and send it as the server. Used for verification that someone is who they say they are.
- `!list` / `!l` - Lists online users.

## Discord commands
- `!list` / `!l` - Lists online users.

## Self hosting
You will need:
- Git
- Gradle
- Java 8+ (JDK)

(All of theses steps happens in the terminal/command line)
1) Clone the repository with the git command (`git clone https://github.com/ayunami2000/ayunpictojava`)
2) Get in the newly created folder with the cd command (`cd ayunpictojava`)
3) Make gradlew executable (`chmod +x gradlew`) (Windows: skip this step)
4) Build the project with gradle (`./gradlew build`) (Windows: `gradlew.bat build`)
5) Once you see the message "BUILD SUCCESSFUL in []s", a new folder will have been created called `build`
6) Go into this build folder, then into the libs folder
7) You will see a file named ayunpictojava-1.0-SNAPSHOT.jar or an equivalent, this is the compiled program!
8) Copy this file to its' own folder for running, and run it (`java -jar ayunpictojava-1.0-SNAPSHOT.jar`) (or whatever the .jar file is named)
9) You should see a line in the terminal saying that the server is running on 127.0.0.1:8080, once you see this you can try it out at http://localhost:8080

### Changing the port and bind address
By default, the application will bind to the local address and port 8080. This means that by default it will not be accessible to anyone else on your network.
To make it accessible, edit the `settings.json` file that is generated after being run at least once, and set host to `0.0.0.0` or `::`. Rerun the program to apply changes.
You can change the port and other configurable settings as well in a similar manner.

### Making tripcodes unique
To make tripcodes unique and reduce the risk of cracking, in the `settings.json` file, set the `tripcode_secret` to something unique and do not share it.

### The captcha
To use the captcha, set the `secret` in the settings.json to your Cloudflare Turnstile captcha secret.
To disable the captcha entirely, edit the `www/index.html` file and search for `let token = false;` and change it to `let token = true;`. Then, remove or comment out the `<div id="captcha" ...` element and the `<script src="https://challenges.cloudflare.com/ ...` element.
