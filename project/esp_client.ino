// This sketch is intended to be used with this Wokwi project:
// https://wokwi.com/projects/459369466274774017

#if defined(ESP8266)
// ESP8266 boards use their own Wi-Fi and HTTP client headers.
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#elif defined(ESP32)
// ESP32 boards expose equivalent APIs through these headers.
#include <WiFi.h>
#include <HTTPClient.h>
#endif

// ArduinoJson is used to build and parse the JSON messages exchanged with the server.
#include <ArduinoJson.h>

// Crypto primitives used by the authentication protocol and protected data channel.
#include <Crypto.h>
#include <AES.h>
#include <SHA256.h>

// Wi-Fi credentials used by the board or by the Wokwi simulator.
const char *WIFI_SSID = "Wokwi-GUEST";
const char *WIFI_PASS = "";

// Backend endpoint used by the ESP device.
const char *SERVER_HOST = "188.218.211.175";
const int SERVER_PORT = 5050;

// Logical identifier sent to the server with every device request.
const char *DEVICE_ID = "ESP8266-01";

// Protocol and demo-sensor constants. The sensor values are fixed here to emulate
// a DHT sensor and battery reading without requiring real hardware.
#define VAULT_SIZE 12
#define KEY_SIZE_BYTES 1
#define DHT_TEMPERATURE 22.5f
#define DHT_HUMIDITY 45.0f
#define BATTERY_VALUE 95

WiFiClient client;

// Timers used to schedule heartbeat, polling, and sensor-data messages.
// They store the millis() timestamp of the last time each action ran.
unsigned long lastHeartbeat = 0;
unsigned long lastPoll = 0;
unsigned long lastSensorSend = 0;

// Monotonic counter included in protected sensor messages to help the server
// detect replayed or out-of-order application data.
uint32_t sensorMessageCounter = 0;

// Non-blocking scheduling intervals used by loop().
const unsigned long HEARTBEAT_INTERVAL = 5000;
const unsigned long POLL_INTERVAL = 3000;
const unsigned long SENSOR_INTERVAL = 10000;
const unsigned long AUTH_START_DELAY_MS = 5000; // Delay after start_auth=true.
const unsigned long AFTER_M2_DELAY_MS = 5000;   // Delay between M2 and M3.
const unsigned long AFTER_AUTH_DELAY_MS = 5000; // Delay before the first /session/data request.

// Authentication and session state.
bool authenticated = false;
String activeSessionId = "";
uint8_t lastC1[3];      // Server-selected vault indexes received in M2.
uint8_t lastC2[3];      // Device-selected vault indexes sent in M3.
uint8_t lastR1[1];      // Server challenge nonce received in M2.
uint8_t lastR2[16];     // Device challenge nonce sent in M3 and checked in M4.
uint8_t lastT1[16];     // Device random material used to derive the session key.
uint8_t lastT2[16];     // Server random material used to derive the session key.
uint8_t sessionKey[16]; // Final application-data key: t1 XOR t2.

// Local vault shared with the server. Authentication derives short-lived keys
// from selected vault entries, then updates the vault so future sessions use
// different material.
uint8_t vault[VAULT_SIZE] = {214, 249, 165, 110, 34, 247, 200, 70, 19, 83, 53, 38};

// Base64 alphabet used by the custom encoder/decoder below.
const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// =========================
// Base64 helpers
// =========================

// Encodes raw bytes as a Base64 string.
String base64Encode(const uint8_t *data, size_t len)
{
  String out;
  int val = 0, valb = -6;
  for (size_t i = 0; i < len; i++)
  {
    // Accumulate input bytes in val, then emit 6-bit chunks as Base64 characters.
    val = (val << 8) + data[i];
    valb += 8;
    while (valb >= 0)
    {
      out += b64_table[(val >> valb) & 0x3F];
      valb -= 6;
    }
  }
  // Emit any remaining bits and pad the output length to a multiple of 4.
  if (valb > -6)
    out += b64_table[((val << 8) >> (valb + 8)) & 0x3F];
  while (out.length() % 4)
    out += '=';
  return out;
}

// Returns the Base64 index for a single character.
int b64Index(char c)
{
  if (c >= 'A' && c <= 'Z')
    return c - 'A';
  if (c >= 'a' && c <= 'z')
    return c - 'a' + 26;
  if (c >= '0' && c <= '9')
    return c - '0' + 52;
  if (c == '+')
    return 62;
  if (c == '/')
    return 63;
  return -1;
}

// Decodes a Base64 string into the provided output buffer.
size_t base64Decode(const String &input, uint8_t *out, size_t maxOut)
{
  int val = 0, valb = -8;
  size_t outLen = 0;
  for (size_t i = 0; i < input.length(); i++)
  {
    char c = input[i];
    // '=' marks the padding area, so decoding can stop there.
    if (c == '=')
      break;
    int idx = b64Index(c);
    // Ignore characters outside the Base64 alphabet.
    if (idx < 0)
      continue;
    val = (val << 6) + idx;
    valb += 6;
    if (valb >= 0)
    {
      // Do not write past the caller-provided output buffer.
      if (outLen < maxOut)
      {
        out[outLen++] = (uint8_t)((val >> valb) & 0xFF);
      }
      valb -= 8;
    }
  }
  return outLen;
}

// =========================
// Cryptographic utilities
// =========================

// Computes SHA-256 over a byte buffer.
void sha256Bytes(const uint8_t *data, size_t len, uint8_t out[32])
{
  SHA256 sha;
  sha.reset();
  sha.update(data, len);
  sha.finalize(out, 32);
}

// Derives a 128-bit AES key by hashing the input material and taking the first 16 bytes.
void deriveAesKey(const uint8_t *material, size_t len, uint8_t out16[16])
{
  uint8_t digest[32];
  sha256Bytes(material, len, digest);
  // AES128 needs exactly 16 bytes. The first half of SHA-256 is used as the key.
  memcpy(out16, digest, 16);
}

// Computes HMAC-SHA256 using a fixed 64-byte SHA-256 block size.
void hmacSha256(const uint8_t *key, size_t keyLen, const uint8_t *message, size_t msgLen, uint8_t out[32])
{
  uint8_t k0[64];
  memset(k0, 0, sizeof(k0));

  // HMAC normalizes the key to the SHA-256 block size. Long keys are first
  // compressed, while shorter keys are copied and padded with zeroes.
  if (keyLen > 64)
  {
    sha256Bytes(key, keyLen, k0);
  }
  else
  {
    memcpy(k0, key, keyLen);
  }

  uint8_t ipad[64];
  uint8_t opad[64];
  for (int i = 0; i < 64; i++)
  {
    // Inner and outer pads are fixed constants defined by HMAC.
    ipad[i] = k0[i] ^ 0x36;
    opad[i] = k0[i] ^ 0x5c;
  }

  // inner = SHA256((key XOR ipad) || message)
  uint8_t inner[32];
  SHA256 s1;
  s1.reset();
  s1.update(ipad, 64);
  s1.update(message, msgLen);
  s1.finalize(inner, 32);

  // out = SHA256((key XOR opad) || inner)
  SHA256 s2;
  s2.reset();
  s2.update(opad, 64);
  s2.update(inner, 32);
  s2.finalize(out, 32);
}

// Converts binary data to a lowercase hexadecimal string.
String bytesToHex(const uint8_t *data, size_t len)
{
  const char *hex = "0123456789abcdef";
  String out;
  out.reserve(len * 2);

  for (size_t i = 0; i < len; i++)
  {
    out += hex[(data[i] >> 4) & 0x0F];
    out += hex[data[i] & 0x0F];
  }

  return out;
}

// XORs two equal-length buffers and stores the result in out.
void xorBuffers(const uint8_t *a, const uint8_t *b, uint8_t *out, size_t len)
{
  for (size_t i = 0; i < len; i++)
    out[i] = a[i] ^ b[i];
}

// Computes a one-byte secret by XORing three entries selected from the vault.
uint8_t computeK(const uint8_t indices[3])
{
  // C1 and C2 contain vault indexes, not secret values. The secret is reconstructed
  // locally by XORing the selected vault bytes.
  uint8_t k = vault[indices[0]];
  k ^= vault[indices[1]];
  k ^= vault[indices[2]];
  return k;
}

// =========================
// Manual AES-CBC helpers
// =========================

// Applies PKCS#7 padding so the plaintext length becomes a multiple of 16 bytes.
size_t pkcs7Pad(const uint8_t *in, size_t inLen, uint8_t *out)
{
  size_t blockSize = 16;
  size_t padLen = blockSize - (inLen % blockSize);
  memcpy(out, in, inLen);
  // Each padding byte stores the number of padding bytes added.
  for (size_t i = 0; i < padLen; i++)
    out[inLen + i] = (uint8_t)padLen;
  return inLen + padLen;
}

// Removes PKCS#7 padding and validates that all padding bytes are correct.
bool pkcs7Unpad(uint8_t *data, size_t &len)
{
  if (len == 0 || (len % 16) != 0)
    return false;
  uint8_t padLen = data[len - 1];
  if (padLen == 0 || padLen > 16)
    return false;
  // Reject malformed padding instead of silently accepting corrupted plaintext.
  for (size_t i = 0; i < padLen; i++)
  {
    if (data[len - 1 - i] != padLen)
      return false;
  }
  len -= padLen;
  return true;
}

// Encrypts plaintext with AES-128-CBC, prefixes the IV, and returns Base64(IV || ciphertext).
String aesCbcEncryptToBase64(const uint8_t key[16], const uint8_t *plaintext, size_t plaintextLen)
{
  AES128 aes;
  aes.setKey(key, 16);

  // A fresh IV is generated for each encrypted message.
  uint8_t iv[16];
  for (int i = 0; i < 16; i++)
    iv[i] = (uint8_t)random(0, 256);

  uint8_t padded[256];
  size_t paddedLen = pkcs7Pad(plaintext, plaintextLen, padded);

  // CBC keeps the previous ciphertext block. For the first block, the IV is used.
  uint8_t prev[16];
  memcpy(prev, iv, 16);

  // Output format: first 16 bytes are the IV, followed by ciphertext blocks.
  uint8_t cipher[272];
  memcpy(cipher, iv, 16);

  for (size_t offset = 0; offset < paddedLen; offset += 16)
  {
    uint8_t block[16];
    // CBC encryption block: AES(plaintext_block XOR previous_cipher_block).
    xorBuffers(padded + offset, prev, block, 16);

    uint8_t enc[16];
    aes.encryptBlock(enc, block);

    memcpy(cipher + 16 + offset, enc, 16);
    // The freshly encrypted block becomes the previous block for the next round.
    memcpy(prev, enc, 16);
  }

  return base64Encode(cipher, 16 + paddedLen);
}

// Decodes Base64(IV || ciphertext), decrypts it with AES-128-CBC, and removes PKCS#7 padding.
bool aesCbcDecryptFromBase64(const uint8_t key[16], const String &b64, uint8_t *outPlain, size_t &outLen)
{
  AES128 aes;
  aes.setKey(key, 16);

  uint8_t buffer[272];
  size_t totalLen = base64Decode(b64, buffer, sizeof(buffer));
  // A valid CBC packet must contain an IV plus at least one ciphertext block.
  if (totalLen < 32 || (totalLen % 16) != 0)
    return false;

  uint8_t iv[16];
  memcpy(iv, buffer, 16);

  size_t bodyLen = totalLen - 16;
  uint8_t prev[16];
  memcpy(prev, iv, 16);

  for (size_t offset = 0; offset < bodyLen; offset += 16)
  {
    uint8_t dec[16];
    aes.decryptBlock(dec, buffer + 16 + offset);

    uint8_t plainBlock[16];
    // CBC decryption block: AES^-1(cipher_block) XOR previous_cipher_block.
    xorBuffers(dec, prev, plainBlock, 16);

    memcpy(outPlain + offset, plainBlock, 16);
    memcpy(prev, buffer + 16 + offset, 16);
  }

  outLen = bodyLen;
  return pkcs7Unpad(outPlain, outLen);
}

// =========================
// HTTP helpers
// =========================

// Builds the full HTTP URL from a relative API path.
String buildURL(const String &path)
{
  // The sketch uses plain HTTP because the encryption/authentication layer is
  // implemented at the application protocol level.
  return String("http://") + SERVER_HOST + ":" + String(SERVER_PORT) + path;
}

// Sends a JSON body with HTTP POST and stores both response body and status code.
bool httpPostJson(const String &path, const String &body, String &response, int &httpCode)
{
  HTTPClient http;
  // A longer timeout helps during simulations or slow Wi-Fi connections.
  http.setTimeout(15000);
  String url = buildURL(path);

  Serial.print("[HTTP POST] ");
  Serial.println(url);

  if (!http.begin(client, url))
  {
    Serial.println("[HTTP POST] begin failed");
    return false;
  }

  http.addHeader("Content-Type", "application/json");
  // The caller receives both the numeric HTTP status and the response body so it
  // can decide whether the protocol step succeeded.
  httpCode = http.POST(body);
  response = http.getString();

  Serial.print("[HTTP POST] code = ");
  Serial.println(httpCode);

  http.end();
  return true;
}

// Sends an HTTP GET request and stores both response body and status code.
bool httpGet(const String &path, String &response, int &httpCode)
{
  HTTPClient http;
  // Keep the timeout aligned with POST requests for consistent network behavior.
  http.setTimeout(15000);
  String url = buildURL(path);

  Serial.print("[HTTP GET] ");
  Serial.println(url);

  if (!http.begin(client, url))
  {
    Serial.println("[HTTP GET] begin failed");
    return false;
  }

  // Store the raw server response. Some callers parse it as JSON afterwards.
  httpCode = http.GET();
  response = http.getString();

  Serial.print("[HTTP GET] code = ");
  Serial.println(httpCode);

  http.end();
  return true;
}

// Waits for the requested amount of time while printing progress dots on Serial.
void waitWithProgress(const char *label, unsigned long ms)
{
  // These waits are intentionally blocking because the protocol sequence needs
  // visible pacing for demos and debugging.
  Serial.print(label);
  Serial.print(" (");
  Serial.print(ms / 1000);
  Serial.println("s)");

  unsigned long start = millis();
  while (millis() - start < ms)
  {
    Serial.print(".");
    delay(500);
  }
  Serial.println();
}

// =========================
// Wi-Fi
// =========================

// Connects the device to Wi-Fi and prints the resulting local IP address.
void connectWiFi()
{
  Serial.println();
  Serial.println("[WIFI] Connecting...");

  // Station mode means the ESP connects to an existing access point.
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  // Try for about 20 seconds: 40 attempts * 500 ms.
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 40)
  {
    delay(500);
    Serial.print(".");
    attempts++;
  }

  Serial.println();

  if (WiFi.status() == WL_CONNECTED)
  {
    Serial.println("[WIFI] Connected");
    Serial.print("[WIFI] Local IP: ");
    Serial.println(WiFi.localIP());
  }
  else
  {
    Serial.print("[WIFI] Failed, status = ");
    Serial.println(WiFi.status());
  }
}

// =========================
// Authentication protocol
// =========================

// Periodically tells the backend that this device is online.
void sendHeartbeat()
{
  // Heartbeats let the server know the device is reachable and how often it polls.
  StaticJsonDocument<128> doc;
  doc["device_id"] = DEVICE_ID;
  doc["polling_interval_seconds"] = 5;

  String body;
  serializeJson(doc, body);

  String response;
  int httpCode = 0;
  httpPostJson("/device/heartbeat", body, response, httpCode);
}

// Polls the backend to check whether the device should start authentication.
bool checkPending()
{
  String response;
  int httpCode = 0;

  // The device stays idle until the backend explicitly asks it to start auth.
  if (!httpGet("/device/pending?device_id=" + String(DEVICE_ID), response, httpCode))
  {
    return false;
  }

  // Non-200 responses are treated as "nothing to do" to keep the loop resilient.
  if (httpCode != 200)
    return false;

  StaticJsonDocument<256> doc;
  // Invalid JSON is ignored instead of starting an authentication with bad data.
  if (deserializeJson(doc, response))
    return false;

  bool startAuth = doc["start_auth"] | false;
  Serial.print("[POLL] start_auth = ");
  Serial.println(startAuth ? "true" : "false");
  return startAuth;
}

// Chooses three vault indexes for C2 that are different from the indexes used in C1.
void chooseDistinctC2(const uint8_t c1[3], uint8_t c2[3])
{
  int count = 0;
  for (uint8_t i = 0; i < VAULT_SIZE && count < 3; i++)
  {
    bool present = false;
    for (int j = 0; j < 3; j++)
    {
      // Do not reuse a C1 index in C2.
      if (c1[j] == i)
        present = true;
    }
    if (!present)
      c2[count++] = i;
  }
}

// Creates a simple unique session identifier from time and a random suffix.
String buildSessionId()
{
  // This is not a cryptographic session ID. It only needs to be unique enough
  // for the server to correlate the messages of a single authentication run.
  String sid = String(micros(), HEX);
  sid += "-";
  sid += String(millis());
  sid += "-";
  sid += String(random(1000, 9999));
  return sid;
}

// Updates the local vault after authentication using an HMAC over the protocol transcript.
void updateVaultLocal()
{
  // The transcript mirrors the authentication values that both sides know after
  // M4. It must be serialized in the same field order expected by the server.
  StaticJsonDocument<256> doc;
  doc["session_id"] = activeSessionId;

  JsonArray c1Arr = doc.createNestedArray("C1");
  for (int i = 0; i < 3; i++)
    c1Arr.add(lastC1[i]);

  doc["r1"] = base64Encode(lastR1, 1);
  doc["t1"] = base64Encode(lastT1, 16);

  JsonArray c2Arr = doc.createNestedArray("C2");
  for (int i = 0; i < 3; i++)
    c2Arr.add(lastC2[i]);

  doc["r2"] = base64Encode(lastR2, 16);
  doc["t2"] = base64Encode(lastT2, 16);

  String transcript;
  serializeJson(doc, transcript);

  uint8_t digest[32];
  // Use the transcript and current vault to create update material. This keeps
  // the local vault synchronized with the server after a successful session.
  hmacSha256((const uint8_t *)transcript.c_str(), transcript.length(), vault, VAULT_SIZE, digest);

  for (int i = 0; i < VAULT_SIZE; i++)
  {
    // Only the first VAULT_SIZE digest bytes are needed to refresh the vault.
    vault[i] ^= digest[i];
  }

  Serial.println("[VAULT] updated locally");
}

// Runs the full mutual-authentication exchange with the backend.
bool runAuthentication()
{
  // Every authentication attempt gets a fresh session ID.
  activeSessionId = buildSessionId();

  // M1: notify the server that this device wants to start a new authentication session.
  StaticJsonDocument<128> startDoc;
  startDoc["device_id"] = DEVICE_ID;
  startDoc["session_id"] = activeSessionId;

  String startBody;
  serializeJson(startDoc, startBody);

  String startResp;
  int startCode = 0;

  Serial.println("[AUTH] sending M1 -> /auth/start");

  // The server replies with M2 if it accepts the session start.
  if (!httpPostJson("/auth/start", startBody, startResp, startCode) || startCode != 200)
  {
    Serial.println("[AUTH] /auth/start error");
    Serial.println(startResp);
    return false;
  }

  // M2: receive C1 and r1 from the server.
  StaticJsonDocument<256> m2Doc;
  if (deserializeJson(m2Doc, startResp))
  {
    Serial.println("[AUTH] invalid M2 response");
    return false;
  }

  // C1 selects three vault positions used to derive the M3 encryption key.
  JsonArray c1Arr = m2Doc["C1"].as<JsonArray>();
  for (int i = 0; i < 3; i++)
    lastC1[i] = c1Arr[i];

  // r1 is the server challenge that the device must echo back inside M3.
  String r1b64 = m2Doc["r1"].as<String>();
  if (base64Decode(r1b64, lastR1, sizeof(lastR1)) != 1)
  {
    Serial.println("[AUTH] invalid r1");
    return false;
  }

  Serial.println("[AUTH] M2 received successfully");
  waitWithProgress("[AUTH] waiting before building and sending M3", AFTER_M2_DELAY_MS);

  // Derive the key used to encrypt M3 from the C1-selected vault entries.
  uint8_t k1 = computeK(lastC1);
  uint8_t aesKeyM3[16];
  // k1 is one byte, so SHA-256 expansion is used before AES-128.
  deriveAesKey(&k1, 1, aesKeyM3);

  // Generate the device challenge material that will be sent in M3.
  for (int i = 0; i < 16; i++)
  {
    // t1 contributes to the final session key; r2 proves server liveness in M4.
    lastT1[i] = (uint8_t)random(0, 256);
    lastR2[i] = (uint8_t)random(0, 256);
  }
  // C2 selects a different set of vault positions for the server response key.
  chooseDistinctC2(lastC1, lastC2);

  // M3: build the plaintext payload, encrypt it, and send it to the server.
  StaticJsonDocument<256> m3Doc;
  m3Doc["r1"] = base64Encode(lastR1, 1);
  m3Doc["t1"] = base64Encode(lastT1, 16);

  JsonArray c2Arr = m3Doc.createNestedArray("C2");
  for (int i = 0; i < 3; i++)
    c2Arr.add(lastC2[i]);

  m3Doc["r2"] = base64Encode(lastR2, 16);

  String m3Plain;
  serializeJson(m3Doc, m3Plain);

  // M3 is encrypted with the key derived from C1, so only a synchronized server
  // with the same vault can read r1, t1, C2, and r2.
  String cipherB64 = aesCbcEncryptToBase64(aesKeyM3, (const uint8_t *)m3Plain.c_str(), m3Plain.length());

  StaticJsonDocument<384> respondDoc;
  respondDoc["device_id"] = DEVICE_ID;
  respondDoc["session_id"] = activeSessionId;
  respondDoc["ciphertext"] = cipherB64;

  String respondBody;
  serializeJson(respondDoc, respondBody);

  String respondResp;
  int respondCode = 0;

  Serial.println("[AUTH] sending M3 -> /auth/respond");

  // A successful response contains M4, encrypted by the server.
  if (!httpPostJson("/auth/respond", respondBody, respondResp, respondCode) || respondCode != 200)
  {
    Serial.println("[AUTH] /auth/respond error");
    Serial.println(respondResp);
    return false;
  }

  // M4: decrypt and validate the server response.
  StaticJsonDocument<384> m4Doc;
  if (deserializeJson(m4Doc, respondResp))
  {
    Serial.println("[AUTH] invalid M4 response");
    return false;
  }

  String m4CipherB64 = m4Doc["ciphertext"].as<String>();

  // Derive the M4 decryption key from K2 and t1.
  uint8_t k2 = computeK(lastC2);
  uint8_t expandedK2[16];
  // K2 is repeated to 16 bytes before mixing it with t1.
  for (int i = 0; i < 16; i++)
    expandedK2[i] = k2;

  uint8_t responseMaterial[16];
  // The server must have used the same C2-derived K2 and the t1 value from M3.
  xorBuffers(expandedK2, lastT1, responseMaterial, 16);

  uint8_t aesKeyM4[16];
  deriveAesKey(responseMaterial, 16, aesKeyM4);

  uint8_t m4Plain[256];
  size_t m4PlainLen = 0;

  if (!aesCbcDecryptFromBase64(aesKeyM4, m4CipherB64, m4Plain, m4PlainLen))
  {
    Serial.println("[AUTH] M4 decryption failed");
    return false;
  }

  // ArduinoJson expects a null-terminated string when parsing from char*.
  m4Plain[m4PlainLen] = 0;

  StaticJsonDocument<256> m4PlainDoc;
  if (deserializeJson(m4PlainDoc, (char *)m4Plain))
  {
    Serial.println("[AUTH] invalid M4 payload");
    return false;
  }

  // The returned r2 must match the challenge generated by this device.
  String r2b64Received = m4PlainDoc["r2"].as<String>();
  uint8_t r2Check[16];
  if (base64Decode(r2b64Received, r2Check, sizeof(r2Check)) != 16)
  {
    Serial.println("[AUTH] invalid received r2");
    return false;
  }

  if (memcmp(r2Check, lastR2, 16) != 0)
  {
    Serial.println("[AUTH] r2 does not match");
    return false;
  }

  // t2 completes the session-key agreement.
  String t2b64 = m4PlainDoc["t2"].as<String>();
  if (base64Decode(t2b64, lastT2, sizeof(lastT2)) != 16)
  {
    Serial.println("[AUTH] invalid t2");
    return false;
  }

  // The final session key is t1 XOR t2.
  xorBuffers(lastT1, lastT2, sessionKey, 16);
  // From this point on, application data can be encrypted with sessionKey.
  authenticated = true;
  sensorMessageCounter = 0;
  updateVaultLocal();

  lastSensorSend = millis();

  Serial.println("[AUTH] mutual authentication completed");
  waitWithProgress("[AUTH] waiting before the first application-data send", AFTER_AUTH_DELAY_MS);
  lastSensorSend = millis();
  return true;
}

// Encrypts and sends one sensor-data message protected by the current session key.
void sendSensorData()
{
  // 1. Build the base payload used as the HMAC input.
  // The HMAC is computed before adding the hmac field itself, so both sides sign
  // exactly the same canonical sensor fields.
  StaticJsonDocument<160> macDoc;
  macDoc["message_counter"] = sensorMessageCounter;
  macDoc["temperature"] = DHT_TEMPERATURE;
  macDoc["humidity"] = DHT_HUMIDITY;
  macDoc["battery"] = BATTERY_VALUE;

  String macPayload;
  serializeJson(macDoc, macPayload);

  // 2. Compute HMAC(sessionKey, payload_json).
  // The HMAC provides integrity and authenticity for the plaintext sensor data
  // before it is encrypted.
  uint8_t macBytes[32];
  hmacSha256(
      sessionKey,
      16,
      (const uint8_t *)macPayload.c_str(),
      macPayload.length(),
      macBytes);

  String macHex = bytesToHex(macBytes, 32);

  // 3. Build the full plaintext payload, including the HMAC.
  // This plaintext will be encrypted, so the HMAC is not exposed on the wire.
  StaticJsonDocument<256> payloadDoc;
  payloadDoc["message_counter"] = sensorMessageCounter;
  payloadDoc["temperature"] = DHT_TEMPERATURE;
  payloadDoc["humidity"] = DHT_HUMIDITY;
  payloadDoc["battery"] = BATTERY_VALUE;
  payloadDoc["hmac"] = macHex;

  String payloadPlain;
  serializeJson(payloadDoc, payloadPlain);

  // 4. Encrypt the payload with the session key.
  // aesCbcEncryptToBase64 returns a transport-safe string containing IV + ciphertext.
  String payloadCipher = aesCbcEncryptToBase64(
      sessionKey,
      (const uint8_t *)payloadPlain.c_str(),
      payloadPlain.length());

  // 5. Wrap the encrypted payload in an HTTP request.
  // The server uses device_id and session_id to find the expected session key.
  StaticJsonDocument<320> doc;
  doc["device_id"] = DEVICE_ID;
  doc["session_id"] = activeSessionId;
  doc["ciphertext"] = payloadCipher;

  String body;
  serializeJson(doc, body);

  String response;
  int httpCode = 0;

  if (!httpPostJson("/session/data", body, response, httpCode))
  {
    Serial.println("[DATA] HTTP error");
    return;
  }

  if (httpCode == 200)
  {
    Serial.println("[DATA] payload sent");
    sensorMessageCounter++; // Increment only after the server accepts the message.
  }
  else if (httpCode == 403 && (response.indexOf("Session expired") >= 0 || response.indexOf("Sessione scaduta") >= 0))
  {
    // A stale session forces the device back into polling/authentication mode.
    Serial.println("[DATA] session expired");
    authenticated = false;
    activeSessionId = "";
  }
  else
  {
    Serial.print("[DATA] error code = ");
    Serial.println(httpCode);
    Serial.println(response);
  }
}

// =========================
// Arduino setup and main loop
// =========================

// Initializes Serial, randomness, and Wi-Fi.
void setup()
{
  Serial.begin(115200);
  // Give the serial monitor a moment to attach after reset.
  delay(2000);
  // Seed Arduino's pseudo-random generator for IVs, nonces, and session IDs.
  randomSeed(micros());

  Serial.println();
  Serial.println("ESP8266 paper-aligned client");
  Serial.println("============================");

  connectWiFi();
}

// Main scheduler: maintain Wi-Fi, send heartbeat, run authentication, and send data.
void loop()
{
  unsigned long now = millis();

  // If Wi-Fi drops, reconnect before attempting any protocol operation.
  if (WiFi.status() != WL_CONNECTED)
  {
    connectWiFi();
    delay(2000);
    return;
  }

  // Heartbeats run regardless of authentication state so the server sees the
  // device as online even before a session is established.
  if (now - lastHeartbeat >= HEARTBEAT_INTERVAL)
  {
    lastHeartbeat = now;
    sendHeartbeat();
  }

  if (!authenticated)
  {
    // While unauthenticated, poll the backend for an explicit start_auth command.
    if (now - lastPoll >= POLL_INTERVAL)
    {
      lastPoll = now;
      if (checkPending())
      {
        waitWithProgress("[AUTH] waiting before starting M1", AUTH_START_DELAY_MS);
        runAuthentication();
      }
    }
  }
  else
  {
    // Once authenticated, periodically send encrypted application data.
    if (now - lastSensorSend >= SENSOR_INTERVAL)
    {
      lastSensorSend = now;
      sendSensorData();
    }
  }

  // Small delay to avoid a tight busy loop on the microcontroller.
  delay(200);
}