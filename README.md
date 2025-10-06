# Canary — ESP32 FTP Honeypot

**Canary** is a tiny, from-scratch FTP honeypot for ESP32 that lures scanners and opportunistic attackers, then **blinks the on-board LED** and (optionally) **fires a Canarytoken** containing the intruder’s IP and UTC timestamp.  
It runs a believable FTP façade with PASV data connections (supports `LIST` and `RETR`), includes a WiFi captive portal for first-time setup and a web **/admin** UI to update the Canary URL without switching the device back into AP mode.

---

## Features

- Pure ESP32 implementation — **no ESPCanary** dependency.
- WiFiManager captive portal for initial Wi-Fi setup.
- Admin web UI (`/admin`) to update the **Canary URL** and FTP labels while the device is running (no AP mode required).
- LED alert: GPIO **2** stays **LOW (off)** after boot; on first intrusion it **BLINKS** until reset.
- Canarytoken GET with query parameters:
  - `src=Canary`
  - `evt` — one of `connect`, `auth`, `list`, `retr` (what triggered the alert)
  - `ip` — intruder IPv4 address
  - `t` — UTC ISO-8601 timestamp (or uptime fallback if NTP not synced)
- Real PASV data channel; supports `LIST` and `RETR` with a small fake file set.
- Config persistence via **LittleFS** (`/config.json`).

---

## Project layout (suggested)

```
canary-honeypot/
├─ src/
│  └─ canary_honeypot.ino      # the ESP32 sketch
├─ platformio.ini              # optional PlatformIO project file
├─ README.md
└─ LICENSE
```

---

## Hardware

- **ESP32 dev board** (e.g. ESP32-DevKitC / DOIT ESP32 DEVKIT V1)
- On-board LED wired to **GPIO 2** (default). If your board uses a different LED pin, change `LED_PIN` in the sketch.

> Power LED (red) stays on — the controlled LED is the GPIO one.

---

## Software requirements

- Arduino IDE (or PlatformIO)
- ESP32 Arduino core installed
- Libraries (install from Library Manager):
  - `WiFiManager` (tzapu)
  - `ArduinoJson`
- LittleFS support (included in the ESP32 core)

---

## Quick install & flash (Arduino IDE)

1. Copy `canary_honeypot.ino` into your Arduino project (or open it).
2. In Arduino IDE: **Tools → Board → ESP32 Dev Module** (or select your board).
3. **Verify** and **Upload**.

---

## First boot — captive portal

- On first run (no stored Wi-Fi), the device creates an AP named **`Canary-Setup`**.
- Connect to that AP and open the captive portal to:
  - Provide your Wi-Fi SSID & password
  - (Optionally) paste a Canarytoken / webhook URL
- After saving the portal data, the device will join your Wi-Fi.

---

## Admin UI (change Canary URL without AP)

1. Find the device IP (Serial Monitor prints it on boot, or check your router).
2. Open `http://<device-ip>/admin`.
3. Edit the **Canary URL** and the FTP Username/Password *labels* (labels are cosmetic) and click **Save**.
4. New settings are persisted to LittleFS immediately.

---

## FTP behavior & supported commands

- Control connection: **port 21**
- Supported control commands (plausible responses):
  - `USER`, `PASS`, `SYST`, `FEAT`, `PWD`, `TYPE`, `NOOP`, `PASV`, `LIST`, `RETR`, `QUIT`
- **PASV**: server opens an ephemeral data port in **20000–20999** and replies with a `227` containing the chosen port.
- **LIST**: returns a fake Unix-style directory listing (two demo files).
- **RETR <filename>**: returns fake file contents for the demo files.

---

## Intrusion detection behavior

On the **first** suspicious event (connect, auth, list, or retr):

1. The on-board LED starts **blinking** (latched until you reset the device).
2. If you set a Canary URL, the device performs an HTTP GET to your URL with appended parameters:

```
GET <your_canary_url>?src=Canary&evt=<connect|auth|list|retr>&ip=<A.B.C.D>&t=<YYYY-MM-DDTHH:MM:SSZ>
```

- `t` is ISO-8601 UTC (if NTP synced) or a fallback uptime string if time is not yet synced.
- The device fires the Canary on the *first* event and continues blinking thereafter. If you prefer repeated events, the code can be modified.

---

## Config file (`/config.json`)

Stored in LittleFS, example:

```json
{
  "canary": "https://your-canary-url",
  "ftpUser": "anonymous",
  "ftpPass": "%"
}
```

- `canary` — the base token/webhook URL (Canary will append query parameters automatically).
- `ftpUser` / `ftpPass` — labels shown in admin UI (cosmetic).

You can edit these via `/admin` without entering AP mode.

---

## Creating a Canarytoken (step-by-step)

You can use any service that exposes a URL which triggers an alert when fetched (e.g., Canarytokens.org, webhook.site, or your own webhook).

### Option A — Canarytokens.org (example)
1. Visit https://canarytokens.org.
2. Choose **Web** / **Web Bug** / **HTTP** token type (names vary).
3. Provide any required info (email for alerts, label, etc.) and generate the token.
4. Copy the generated token URL (e.g. `https://canarytokens.org/abcd1234`).
5. In Canary admin (`http://<device-ip>/admin`) paste the token URL into the **Canary URL** field and **Save**.

### Option B — webhook.site or your own endpoint
- Create a webhook endpoint that logs incoming GET requests or notifies you.
- Use that URL as the Canary URL in the device admin UI.

### What Canary will send
When the device fires the token, it appends parameters:

```
?src=Canary&evt=<connect|auth|list|retr>&ip=<A.B.C.D>&t=<ISO8601_UTC_or_uptime>
```

So full example:

```
GET https://canarytokens.org/abcd1234?src=Canary&evt=connect&ip=10.0.0.55&t=2025-10-06T13:45:02Z
```

---

## Test Canary button — add instant test to admin UI

A **Test Canary** button lets you verify the Canary token from the device immediately (sends `evt=test` and current IP/time). Below are the minimal code snippets to add to your sketch.

### 1) Add an admin button in the `/admin` HTML

Replace or extend the admin HTML form with a test button (example snippet — insert into the `handleRoot()` HTML where the form is rendered):

```html
<form method="POST" action="/setcanary">
  Canary URL: <input type="text" name="canary" style="width:80%" value="..."><br><br>
  FTP Username (label): <input type="text" name="ftpuser" value="..."><br><br>
  FTP Password (label): <input type="text" name="ftppass" value="..."><br><br>
  <input type="submit" value="Save">
</form>

<form method="POST" action="/testcanary" style="margin-top:10px;">
  <input type="submit" value="Test Canary (send evt=test)">
</form>
```

### 2) Add a new POST handler in `setup()`:

```cpp
adminServer.on("/setcanary", HTTP_POST, handleSetCanary);
adminServer.on("/testcanary", HTTP_POST, handleTestCanary);
```

### 3) Add `handleTestCanary()` handler to your sketch:

```cpp
void handleTestCanary() {
  // Use last known intruder IP if set, else use device IP
  String ip = lastIntruderIP.length() ? lastIntruderIP : WiFi.localIP().toString();
  fireCanary("test", ip);    // same function used for real triggers
  String html = "<!doctype html><html><body style='font-family:sans-serif'>";
  html += "<h3>Test Canary fired</h3>";
  html += "<p>URL: " + canaryURL + "</p>";
  html += "<p>IP used: " + ip + "</p>";
  html += "<p><a href='/admin'>Back to admin</a></p>";
  html += "</body></html>";
  adminServer.send(200, "text/html", html);
}
```

This will send a single GET to your configured Canary URL with `evt=test`, `ip`, and `t`. Use this to quickly verify alerts are delivered.

---

## Testing the Canary URL manually

From any machine (or using `curl`):

```bash
curl "https://<token-url>?src=Canary&evt=test&ip=1.2.3.4&t=2025-10-06T13:45:02Z"
```

This helps verify that your token provider accepts GET requests and that alerts are delivered.

---

## Troubleshooting

- **No captive portal**: Connect to SSID `Canary-Setup` and open `http://192.168.4.1/`.
- **Cannot find IP**: Check Serial Monitor at 115200 baud — the sketch prints the device IP at boot.
- **LED never blinks**: Ensure your board’s user LED is actually on **GPIO 2** or update `LED_PIN`.
- **Canary not firing**: Verify the URL in `/admin` and ensure the device has Internet access.
- **LIST/RETR failing**: Ensure your FTP client uses **PASV**.

---

## PlatformIO (optional)

If you prefer PlatformIO for builds, here is a minimal `platformio.ini` you can drop into the project root:

```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino
monitor_speed = 115200
lib_deps =
  tzapu/WiFiManager@^0.18.0
  bblanchon/ArduinoJson@^6.20.0
build_flags = 
  -DCORE_DEBUG_LEVEL=0
```

> Adjust `lib_deps` versions if you need different releases. `LittleFS` is provided by the ESP32 Arduino core.

---

## Customization ideas

- Serve real files from LittleFS instead of fake contents.
- Log intruder activity (commands, timestamps) to LittleFS for later review.
- Change blink pattern or switch to solid **ON** after N seconds of blinking.
- Add JSON `/api/status` endpoints for automated monitoring.
- Allow multiple Canary URLs or periodic re-firing for repeated alerts.

---

## Contributing

Contributions welcome! Ideas that help the project:
- Improve FTP realism (directory trees, timestamps).
- Add persistent logging of intruder session data.
- Add authenticated admin UI or TLS for the control web server.
- Add PlatformIO examples or CI build scripts.

---

## License

This project is released under the **MIT License**. Include this `LICENSE` file in your repo and/or copy the text below.

```
MIT License

Copyright (c) 2025 Mike de Landgraaf

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```
