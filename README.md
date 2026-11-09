# PictoRust

**PictoRust** is the new name for the ongoing Rust and TypeScript modernization of the original Nintendo DS PictoChat browser implementation.

> **Original creator credit:** This project is derived from [ayunami2000/ayunpictojava](https://github.com/ayunami2000/ayunpictojava). The original Java/browser work, DS sprites and bundled font are retained with attribution. See [CREDITS.md](CREDITS.md) for rights and provenance; this fork is independent and unaffiliated with Nintendo.

<p align="center"><strong>We trust in PictoRust!</strong></p>

<p align="center"><em>The PictoChat experience we remember. The encryption we expect today.</em></p>

**Read this story:** [English](#how-it-all-started) · [Deutsch](#wie-alles-begann)

## How it all started

**PictoRust** did not begin with a business plan. It began when my friend
**Alperen** showed me **picto.app**. It immediately brought back the feeling
of PictoChat on the Nintendo DS: simple chat rooms, little drawings, and
the joy of talking to people through a tiny, familiar interface.

Curiosity quickly turned into a code review. We started asking questions
that matter whenever a messenger claims to be private: **Who can read the
messages? Where is encryption applied? What can the server see or store?**
The Java-based implementation and the lack of privacy and encryption
assurances that *we could independently verify* left us dissatisfied.
We wanted to build a version where the chat server would not need access
to users' message content.

That experience inspired us to take a different approach. Instead of
simply complaining, we started **PictoRust**: a recreation of the original
PictoChat experience with a **Rust relay**, **OpenMLS-based end-to-end
encryption**, straightforward group invitations, the familiar two-screen
Nintendo DS interface, and minimal unnecessary server-side data handling.

**An important distinction:** These were our concerns and motivations,
not proof that picto.app actually monitored private conversations or
misused user data. Reviewing code alone cannot establish how a service
operator behaves in practice.

> **We trust in PictoRust!** Not because anyone should blindly trust a
> server, but because privacy should be supported by technology that can
> be inspected, tested, and challenged.

## Our goals

- **Preserve the original experience:** Two DS screens, rooms A–E,
  the original-style keyboard, drawing tools, and pixel-perfect PDF exports.
- **Make privacy a technical property:** OpenMLS encrypts chat content on
  users' devices; the Rust relay does not decrypt message bodies.
- **Keep it simple:** Choose a room, share an invite link, and chat without
  visible cryptography controls.
- **Stay transparent:** Publish the implementation, tests, limitations,
  and proper credits for the upstream project.
- **Earn trust, don't demand it:** PictoRust is not yet independently
  security-audited or production-ready for sensitive conversations.

## Current release status

**PictoRust v0.2.0-rc.2** is a publicly available **source-code technical
pre-release**, not a certified secure messenger. Automated browser tests
cover the original UI, OpenMLS invitations, drawings, PDF export,
HTTPS/WSS transport, and one limited safe reconnect while the group
owner remains online.

The P0 development branch contains a **volatile ciphertext-only** relay
replay window (64 frames, 128 KiB maximum per room, 30-minute TTL,
whichever fills first). The server does not receive MLS plaintext, but
does temporarily retain encrypted traffic in RAM. It is **not** durable,
does not survive server restarts and is not yet the public default chat's
trusted offline catch-up. The encrypted IndexedDB checkpoint vault in that
branch is likewise experimental until authenticated epoch reconciliation
is wired into the chat.

A stable release still needs secure, durable MLS state recovery after
browser restarts, long-offline synchronization, stronger identity
verification, independent security assessment, and real-device
deployment testing.

The maintainer reports having received permission to use the required
third-party materials. The precise redistribution scope for source,
graphics, fonts, and modifications still needs to be documented before
shipping licensed binary packages. See [CREDITS.md](CREDITS.md) and the
[permissions record](docs/RIGHTS_RECORD.md).

**References:** [Release notes](docs/RELEASE_NOTES_v0.2.0-rc.2.md) ·
[Release readiness](docs/RELEASE_CANDIDATE.md) ·
[Deployment guide](deploy/README.md).

---

## Wie alles begann

Die Idee zu **PictoRust** entstand, als mein Freund **Alperen** mir
**picto.app** zeigte. Sofort war dieses Nintendo-DS-PictoChat-Gefühl
wieder da: kleine Chaträume, Zeichnungen und eine bewusst einfache
Bedienung.

Aus Neugier wurde ein technischer Code-Review. Dabei fragten wir uns:
**Wer kann Nachrichten lesen? Wo findet die Verschlüsselung statt?
Welche Daten kann der Server sehen oder speichern?** Die Java-basierte
Implementierung und die Datenschutz- und Verschlüsselungsgarantien,
die wir selbst nicht ausreichend nachvollziehen konnten, überzeugten
uns nicht. Wir wollten einen Messenger entwickeln, bei dem der
Chatserver den Nachrichteninhalt nicht entschlüsseln muss.

So entstand **PictoRust** – mit einem **Rust-Relay**, **OpenMLS-basierter
Ende-zu-Ende-Verschlüsselung**, einfachen Gruppeneinladungen und dem
vertrauten Nintendo-DS-Design.

**Wichtig:** Diese Geschichte beschreibt unsere damaligen Bedenken
und Motivation. Sie ist kein Nachweis dafür, dass picto.app tatsächlich
Unterhaltungen überwacht oder Daten missbraucht. Allein aus einem
Code-Review lässt sich das Verhalten eines Betreibers nicht beweisen.

> **We trust in PictoRust!** Nicht, weil man einem Server blind
> vertrauen sollte, sondern weil Privatsphäre durch überprüfbare
> Technik gestützt werden muss.

## Unsere Ziele

- **Originalgefühl bewahren:** Zwei DS-Bildschirme, Räume A–E,
  Tastatur, Zeichnungen und pixelgetreue PDF-Exporte.
- **Privatsphäre technisch umsetzen:** OpenMLS verschlüsselt
  Nachrichten auf den Endgeräten; der Rust-Relay kann sie nicht lesen.
- **Einfach bleiben:** Raum auswählen, Link teilen, chatten –
  ohne Kryptografie-Menüs.
- **Offen entwickeln:** Quellcode, Tests, Einschränkungen und Credits
  transparent dokumentieren.
- **Vertrauen verdienen:** PictoRust ist noch nicht unabhängig
  sicherheitsgeprüft und nicht für sensible Produktivchats freigegeben.

## Aktueller Release-Stand

**PictoRust v0.2.0-rc.2** ist als öffentliche
**Quellcode-Technical-Preview** erschienen, nicht als Stable Release.
Automatisierte Tests prüfen die Originaloberfläche, MLS-Einladungen,
Zeichnungen, PDF, HTTPS/WSS und einen begrenzten sicheren
Wiederbeitritt bei laufendem Gruppeninhaber.

Für Stable fehlen insbesondere die sichere MLS-Wiederherstellung nach
Browserneustarts, längere Offline-Synchronisierung, stärkere
Identitätsprüfung, ein unabhängiger Security-Review und reale
Geräte-/Deployment-Tests.

Die Projektverantwortlichen geben an, eine Nutzungserlaubnis für die
benötigten Materialien erhalten zu haben. Ihr genauer Umfang muss
vor der Verteilung von Binärpaketen dokumentiert sein.
Siehe [CREDITS.md](CREDITS.md) und
[Rechte-Nachweis](docs/RIGHTS_RECORD.md).

---

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
