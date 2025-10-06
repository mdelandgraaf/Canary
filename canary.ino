/*********************************************************
 * Canary - ESP32 Fake FTP Honeypot + WiFiManager + PASV LIST/RETR
 * + Admin web form to change Canary URL (no AP needed)
 * + Canary fires with intruder IP and UTC time
 *
 * - LED on GPIO 2: LOW after boot; BLINKS after first intrusion (latched)
 * - NTP time sync (UTC). If NTP not ready, falls back to uptime
 *********************************************************/

#include <WiFi.h>
#include <WebServer.h>
#include <WiFiManager.h>
#include <ArduinoJson.h>
#include <LittleFS.h>
#include <HTTPClient.h>
#include <time.h>

// ------------------- Config -------------------
#define AP_NAME      "Canary-Setup"
#define CONFIG_PATH  "/config.json"

// LED: GPIO2, LOW at boot (off), blink on intrusion
const uint8_t LED_PIN = 2;
#define LED_OFF_LEVEL LOW
#define LED_ON_LEVEL  HIGH
const uint32_t BLINK_INTERVAL_MS = 400;

// Fake FTP replies
const char* FTP_BANNER = "220 (Fake FTP Service)\r\n";
const char* FTP_USEROK = "331 User name okay, need password\r\n";
const char* FTP_LOGGED = "230 User logged in, proceed\r\n";
const char* FTP_SYST   = "215 UNIX Type: L8\r\n";
const char* FTP_FEAT   = "211-Features:\r\n UTF8\r\n MDTM\r\n SIZE\r\n PASV\r\n211 End\r\n";
const char* FTP_PWD    = "257 \"/\" is current directory\r\n";
const char* FTP_TYPEOK = "200 Type set to I\r\n";
const char* FTP_NOOP   = "200 NOOP ok\r\n";
const char* FTP_QUIT   = "221 Goodbye\r\n";
const char* FTP_OK     = "200 OK\r\n";
const char* FTP_PRELIM_TRANSFER = "150 Opening data connection\r\n";
const char* FTP_TRANSFER_COMPLETE = "226 Transfer complete\r\n";

// ------------------- Runtime settings (portal + admin) -------------------
String canaryURL = "";            // optional — if set, GET on first intrusion
String ftpUser   = "anonymous";   // cosmetic (not enforced)
String ftpPass   = "%";           // cosmetic (not enforced)

// ------------------- State -------------------
WebServer adminServer(80);
WiFiServer ftpServer(21);
WiFiClient ftpClient;            // control connection
bool clientConnected = false;

bool intrusionLatched   = false;  // set on first FTP connect
bool blinkingActive     = false;
uint32_t lastBlinkTick  = 0;
bool      blinkHigh     = false;

// Intruder info
String lastIntruderIP = "";

// PASV data server
WiFiServer dataServer(0);         // started with .begin(port) when needed
WiFiClient dataClient;
int dataPort = 0;
bool pasvActive = false;

// ------------------- File system / fake files -------------------
struct FakeFile {
  const char* name;
  const char* contents;
};
FakeFile fakeFiles[] = {
  { "README.txt", "Welcome to the public FTP server.\r\nThis is a honeypot.\r\n" },
  { "secret.txt", "TOP SECRET: honeytokens are live.\r\n" }
};
const int fakeFileCount = sizeof(fakeFiles) / sizeof(fakeFiles[0]);

// ------------------- Helpers: LED -------------------
inline void ledInit() { pinMode(LED_PIN, OUTPUT); digitalWrite(LED_PIN, LED_OFF_LEVEL); }
inline void ledOff()  { digitalWrite(LED_PIN, LED_OFF_LEVEL); }
inline void ledOn()   { digitalWrite(LED_PIN, LED_ON_LEVEL); }

void startBlink() {
  blinkingActive = true;
  lastBlinkTick = 0;
  blinkHigh = false;
}

void serviceBlink() {
  if (!blinkingActive) return;
  uint32_t now = millis();
  if (now - lastBlinkTick >= BLINK_INTERVAL_MS) {
    lastBlinkTick = now;
    blinkHigh = !blinkHigh;
    digitalWrite(LED_PIN, blinkHigh ? LED_ON_LEVEL : LED_OFF_LEVEL);
  }
}

// ------------------- URL encode -------------------
String urlEncode(const String& s) {
  String out; out.reserve(s.length() * 3);
  const char *hex = "0123456789ABCDEF";
  for (size_t i = 0; i < s.length(); ++i) {
    char c = s[i];
    if (('a'<=c && c<='z') || ('A'<=c && c<='Z') || ('0'<=c && c<='9') ||
        c=='-'||c=='_'||c=='.'||c=='~') {
      out += c;
    } else if (c == ' ') {
      out += "%20";
    } else {
      out += '%';
      out += hex[(c >> 4) & 0xF];
      out += hex[c & 0xF];
    }
  }
  return out;
}

// ------------------- Time helpers (UTC ISO8601) -------------------
String timeISO8601UTC() {
  time_t now = time(nullptr);
  if (now < 1700000000) { // not yet synced (rough threshold)
    char buf[40];
    snprintf(buf, sizeof(buf), "uptime_ms_%lu", (unsigned long)millis());
    return String(buf);
  }
  struct tm tm_utc;
  gmtime_r(&now, &tm_utc);
  char buf[32];
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
  return String(buf);
}

// ------------------- Canary trigger -------------------
void fireCanary(const char* evt, const String& ipStr) {
  if (canaryURL.length() == 0) return;

  String t = timeISO8601UTC();
  String url = canaryURL;
  url += (url.indexOf('?') >= 0) ? "&" : "?";
  url += "src=Canary";
  url += "&evt=" + urlEncode(String(evt));
  if (ipStr.length()) url += "&ip=" + urlEncode(ipStr);
  url += "&t=" + urlEncode(t);

  HTTPClient http;
  http.setConnectTimeout(4000);
  http.setTimeout(4000);
  if (http.begin(url)) {
    int code = http.GET();
    Serial.printf("[Canary] GET -> %d (%s)\n", code, url.c_str());
    http.end();
  } else {
    Serial.println("[Canary] HTTP begin failed");
  }
}

// ------------------- Intrusion handler -------------------
void onFirstIntrusion(const char* why) {
  if (intrusionLatched) return;
  intrusionLatched = true;
  Serial.printf("[INTRUSION] %s (LED will BLINK until reset)\n", why);
  startBlink();
  fireCanary(why, lastIntruderIP);
}

// ------------------- FTP helpers -------------------
void ftpSend(const char* s) {
  if (ftpClient && ftpClient.connected()) ftpClient.print(s);
}

String readFtpLine(unsigned long timeoutMs = 400) {
  String line;
  unsigned long t0 = millis();
  while (millis() - t0 < timeoutMs) {
    while (ftpClient && ftpClient.available()) {
      char c = ftpClient.read();
      if (c == '\r') continue;
      if (c == '\n') return line;
      line += c;
      if (line.length() > 1024) return line;
    }
    delay(1);
  }
  return line;
}

String ipCommas(IPAddress ip) {
  char buf[32];
  snprintf(buf, sizeof(buf), "%u,%u,%u,%u", ip[0], ip[1], ip[2], ip[3]);
  return String(buf);
}

int pickPasvPort() {
  return 20000 + (esp_random() % 1000); // 20000..20999
}

bool startPasv() {
  if (pasvActive && dataServer) {
    dataServer.stop();
    pasvActive = false;
    dataPort = 0;
  }
  dataPort = pickPasvPort();
  dataServer = WiFiServer(dataPort);
  dataServer.begin();
  pasvActive = true;
  Serial.printf("[PASV] listening on %d\n", dataPort);
  return true;
}

WiFiClient waitForDataClient(unsigned long timeoutMs = 5000) {
  unsigned long start = millis();
  while (millis() - start < timeoutMs) {
    WiFiClient c = dataServer.available();
    if (c) return c;
    delay(5);
  }
  return WiFiClient();
}

void stopPasv() {
  if (pasvActive) {
    dataServer.stop();
    pasvActive = false;
    dataPort = 0;
  }
}

// Build a plausible Unix-style long listing line
String longListingLine(const char* name, size_t size, const char* dateStr = "Jan 01 00:00") {
  char buf[256];
  snprintf(buf, sizeof(buf), "-rw-r--r-- 1 owner group %6u %s %s\r\n", (unsigned)size, dateStr, name);
  return String(buf);
}

// ------------------- LIST / RETR implementations -------------------
void handleLIST() {
  ftpSend(FTP_PRELIM_TRANSFER);
  WiFiClient dc;
  if (pasvActive) {
    dc = waitForDataClient();
    if (!dc) {
      ftpSend("425 Can't open data connection\r\n");
      stopPasv();
      return;
    }
    for (int i = 0; i < fakeFileCount; ++i) {
      String line = longListingLine(fakeFiles[i].name, strlen(fakeFiles[i].contents), "Oct 01 12:00");
      dc.print(line);
    }
    dc.stop();
    stopPasv();
    ftpSend(FTP_TRANSFER_COMPLETE);
    onFirstIntrusion("list");
    return;
  } else {
    ftpSend("425 Use PASV first\r\n");
    return;
  }
}

void handleRETR(const String& filename) {
  String fname = filename; fname.trim();
  if (fname.startsWith("\"") && fname.endsWith("\"") && fname.length() >= 2)
    fname = fname.substring(1, fname.length()-1);

  const char* contents = nullptr;
  size_t len = 0;
  for (int i = 0; i < fakeFileCount; ++i) {
    if (fname.equalsIgnoreCase(fakeFiles[i].name)) {
      contents = fakeFiles[i].contents;
      len = strlen(contents);
      break;
    }
  }

  if (!contents) { ftpSend("550 File not found\r\n"); return; }

  ftpSend(FTP_PRELIM_TRANSFER);
  WiFiClient dc;
  if (pasvActive) {
    dc = waitForDataClient();
    if (!dc) {
      ftpSend("425 Can't open data connection\r\n");
      stopPasv();
      return;
    }
    dc.write((const uint8_t*)contents, len);
    dc.stop();
    stopPasv();
    ftpSend(FTP_TRANSFER_COMPLETE);
    onFirstIntrusion("retr");
    return;
  } else {
    ftpSend("425 Use PASV first\r\n");
    return;
  }
}

// ------------------- Config (LittleFS) -------------------
bool loadConfig() {
  if (!LittleFS.exists(CONFIG_PATH)) return false;
  File f = LittleFS.open(CONFIG_PATH, "r");
  if (!f) return false;
  StaticJsonDocument<512> doc;
  if (deserializeJson(doc, f)) { f.close(); return false; }
  f.close();
  canaryURL = (const char*)(doc["canary"]  | canaryURL.c_str());
  ftpUser   = (const char*)(doc["ftpUser"] | ftpUser.c_str());
  ftpPass   = (const char*)(doc["ftpPass"] | ftpPass.c_str());
  return true;
}

bool saveConfig() {
  StaticJsonDocument<512> doc;
  doc["canary"]  = canaryURL;
  doc["ftpUser"] = ftpUser;
  doc["ftpPass"] = ftpPass;
  File f = LittleFS.open(CONFIG_PATH, "w");
  if (!f) return false;
  bool ok = serializeJson(doc, f) > 0;
  f.close();
  return ok;
}

// ------------------- WiFiManager -------------------
void openConfigPortal(bool forcePortal) {
  WiFiManager wm;

  WiFiManagerParameter p_canary("canary", "Canarytoken URL (optional)", canaryURL.c_str(), 256);
  WiFiManagerParameter p_user  ("ftpuser","FTP Username (label only)", ftpUser.c_str(), 32);
  WiFiManagerParameter p_pass  ("ftppass","FTP Password (label only)", ftpPass.c_str(), 32);

  wm.addParameter(&p_canary);
  wm.addParameter(&p_user);
  wm.addParameter(&p_pass);

  wm.setConfigPortalTimeout(300); // 5 min

  bool ok = forcePortal ? wm.startConfigPortal(AP_NAME) : wm.autoConnect(AP_NAME);
  if (!ok) { delay(1500); ESP.restart(); }

  canaryURL = p_canary.getValue();
  ftpUser   = p_user.getValue();
  ftpPass   = p_pass.getValue();
  saveConfig();
}

// ------------------- Admin UI -------------------
void handleRoot() {
  String html = F(
    "<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Canary Admin</title></head><body style='font-family:sans-serif'>"
    "<h2>Canary Admin (ESP32)</h2><p>");
  html += F("<b>IP:</b> ");            html += WiFi.localIP().toString();
  html += F("<br><b>LED:</b> ");       html += blinkingActive ? "BLINKING (latched)" : "OFF";
  html += F("<br><b>FTP user/pass labels:</b> "); html += ftpUser + " / " + ftpPass;
  html += F("</p><hr>");

  // Editable form to change Canary URL + FTP user/pass without AP mode
  html += F("<h3>Update Canary URL / FTP labels</h3>"
            "<form method='POST' action='/setcanary'>"
            "Canary URL: <input type='text' name='canary' style='width:80%' value='");
  html += canaryURL;
  html += F("'><br><br>FTP Username (label): <input type='text' name='ftpuser' value='");
  html += ftpUser;
  html += F("'><br><br>FTP Password (label): <input type='text' name='ftppass' value='");
  html += ftpPass;
  html += F("'><br><br><input type='submit' value='Save'></form>");

  html += F("<hr><p><a href='/reconfig'><button>Open WiFi/Token Config Portal</button></a></p>"
            "</body></html>");
  adminServer.send(200, "text/html", html);
}

// POST handler — updates values and saves to LittleFS
void handleSetCanary() {
  if (adminServer.hasArg("canary")) canaryURL = adminServer.arg("canary");
  if (adminServer.hasArg("ftpuser")) ftpUser = adminServer.arg("ftpuser");
  if (adminServer.hasArg("ftppass")) ftpPass = adminServer.arg("ftppass");
  saveConfig();

  String html = "<!doctype html><html><body style='font-family:sans-serif'>";
  html += "<h3>Settings saved</h3>";
  html += "<p>Canary URL: " + canaryURL + "</p>";
  html += "<p>FTP user label: " + ftpUser + "</p>";
  html += "<p>FTP pass label: " + ftpPass + "</p>";
  html += "<p><a href='/admin'>Back to admin</a></p>";
  html += "</body></html>";
  adminServer.send(200, "text/html", html);
}

void handleReconfig() {
  adminServer.send(200, "text/plain", "Re-opening config portal… connect to AP 'Canary-Setup'.");
  delay(300);
  openConfigPortal(true);
}

// ------------------- Fake FTP core -------------------
void serviceFtp() {
  // Accept new connection if none
  if (!clientConnected) {
    WiFiClient newc = ftpServer.available();
    if (newc) {
      ftpClient.stop();
      ftpClient = newc;
      clientConnected = true;
      stopPasv();

      IPAddress rip = ftpClient.remoteIP();
      lastIntruderIP = String(rip[0]) + "." + String(rip[1]) + "." + String(rip[2]) + "." + String(rip[3]);

      Serial.print("[FTP] Connection made from ");
      Serial.println(lastIntruderIP);
      ftpSend(FTP_BANNER);

      onFirstIntrusion("connect");
    }
  }

  if (!clientConnected) return;

  if (!ftpClient.connected()) {
    clientConnected = false;
    ftpClient.stop();
    stopPasv();
    return;
  }

  String cmd = readFtpLine();
  if (cmd.length() == 0) return;

  String ucmd = cmd; ucmd.trim();
  String ucmdUpper = ucmd; ucmdUpper.toUpperCase();

  Serial.printf("[FTP CMD] %s\n", ucmd.c_str());

  if (ucmdUpper.startsWith("USER ")) {
    ftpSend(FTP_USEROK);
  } else if (ucmdUpper.startsWith("PASS ")) {
    ftpSend(FTP_LOGGED);
    onFirstIntrusion("auth");
  } else if (ucmdUpper == "SYST") {
    ftpSend(FTP_SYST);
  } else if (ucmdUpper == "FEAT") {
    ftpSend(FTP_FEAT);
  } else if (ucmdUpper == "PWD" || ucmdUpper == "XPWD") {
    ftpSend(FTP_PWD);
  } else if (ucmdUpper.startsWith("TYPE ")) {
    ftpSend(FTP_TYPEOK);
  } else if (ucmdUpper == "NOOP") {
    ftpSend(FTP_NOOP);
  } else if (ucmdUpper == "QUIT") {
    ftpSend(FTP_QUIT);
    ftpClient.stop();
    clientConnected = false;
    stopPasv();
  } else if (ucmdUpper.startsWith("PASV")) {
    startPasv();
    IPAddress ip = WiFi.localIP();
    int p1 = (dataPort >> 8) & 0xFF;
    int p2 = dataPort & 0xFF;
    String resp = "227 Entering Passive Mode (" + ipCommas(ip) + "," + String(p1) + "," + String(p2) + ")\r\n";
    ftpSend(resp.c_str());
  } else if (ucmdUpper.startsWith("LIST")) {
    handleLIST();
  } else if (ucmdUpper.startsWith("RETR ")) {
    int sp = ucmd.indexOf(' ');
    String fname = (sp >= 0) ? ucmd.substring(sp + 1) : "";
    handleRETR(fname);
  } else if (ucmdUpper.startsWith("PORT ")) {
    ftpSend("200 PORT command acknowledged; please use PASV for data transfers\r\n");
  } else {
    ftpSend(FTP_OK);
  }
}

// ------------------- setup / loop -------------------
void setup() {
  Serial.begin(115200);
  delay(100);

  // LED LOW after boot (off)
  ledInit();

  // FS + config
  LittleFS.begin(true);
  loadConfig();

  // Portal / Wi-Fi (initial)
  openConfigPortal(false);

  // NTP time (UTC)
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  // Non-blocking: timeISO8601UTC() will fall back if not ready

  // Admin routes
  adminServer.on("/", handleRoot);
  adminServer.on("/admin", handleRoot);
  adminServer.on("/setcanary", HTTP_POST, handleSetCanary); // POST form handler
  adminServer.on("/reconfig", handleReconfig);
  adminServer.begin();

  // Start fake FTP server
  ftpServer.begin();
  Serial.println("==== Canary (ESP32 Fake FTP Honeypot) ready ====");
  Serial.print("IP: "); Serial.println(WiFi.localIP());
  Serial.println("LED is LOW after boot; first FTP connection will start BLINKING (latched).");
}

void loop() {
  adminServer.handleClient();
  serviceFtp();
  serviceBlink();
}
