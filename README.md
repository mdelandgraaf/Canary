# Canary — ESP32 FTP Honeypot

**Canary** is a tiny fake FTP honeypot running on an ESP32. It lures scanners and opportunistic attackers, then **blinks the on-board LED** and (optionally) **fires a Canarytoken** containing the intruder’s IP and UTC timestamp.  
This project is self-contained (no ESPCanary dependency) and includes:

- WiFiManager captive portal for initial setup
- Admin web UI to update the Canary URL and FTP labels without entering AP mode
- Real PASV data channel supporting `LIST` and `RETR`
- Config persistence via LittleFS

---

## Features

- From-scratch ESP32 FTP honeypot (no external FTP or Canary libraries)
- LED alert: GPIO **2** stays **LOW (off)** after boot; on first intrusion it **BLINKS** until reset
- Canarytoken GET with `src=Canary`, `evt`, `ip` and `t` (ISO-8601 UTC)
- Admin page at `/admin` to update Canary URL and FTP labels while running
- Real **PASV** data connections, supports `LIST` and `RETR` with fake files
- LittleFS config persistence (`/config.json`)

---

## Hardware

- ESP32 dev board (e.g., ESP32-DevKitC / DOIT ESP32 DEVKIT V1)
- On-board LED on **GPIO 2** (default). Change in sketch if your board differs.

---

## Software prerequisites

- Arduino IDE or PlatformIO
- ESP32 Arduino core
- Libraries (install via Library Manager):
  - `WiFiManager` (tzapu)
  - `ArduinoJson`
- LittleFS is included in ESP32 core

---

## Installation & Usage

1. Copy `canary_honeypot.ino` into your Arduino project.
2. Select your ESP32 board under **Tools → Board**.
3. Compile and upload.

### First boot — captive portal
- If no Wi-Fi credentials are saved, Canary creates an AP named **`Canary-Setup`**.
- Connect to that AP and follow the portal to provide Wi-Fi credentials and (optionally) a Canary token URL.
- After saving, the device joins your Wi-Fi.

### Admin page (no AP needed)
- Visit `http://<device-ip>/admin`.
- Update **Canary URL** and FTP username/password labels (these are cosmetic).
- Click **Save** — changes persist immediately to LittleFS.

---

## FTP behavior

- Control connection listens on **port 21**.
- Supports basic commands: `USER`, `PASS`, `SYST`, `FEAT`, `PWD`, `TYPE`, `NOOP`, `PASV`, `LIST`, `RETR`, `QUIT`.
- `PASV` opens a random data port (20000–20999).
- `LIST` returns a fake Unix-style listing for files:
  - `README.txt`
  - `secret.txt`
- `RETR <filename>` returns fake file contents.

### Intrusion events
On the **first** suspicious event (connect / auth / list / retr):
- LED starts **blinking** and remains blinking until reset.
- If a Canary URL is configured, Canary performs:
