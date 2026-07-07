/*
 * ============================================================================
 * He thong IoT giam sat moi truong - cau hinh (Dual Mode)
 * TICH HOP: DHT11 (GPIO4) + MQ2 (GPIO34) + BH1750 (I2C: GPIO21, GPIO22)
 * ============================================================================
 */

#include <WiFi.h>
#include <WiFiClient.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <DHT.h>
#include <BH1750.h> 
#include <Wire.h>   
#include <ArduinoJson.h>
#include "mbedtls/md.h"
#include <time.h> 

//  CẤU HÌNH BẬT / TẮT BẢO MẬT 
#define ENABLE_TLS   1   
#define ENABLE_HMAC  1   

const char* WIFI_SSID     = "Nhóm 30";
const char* WIFI_PASSWORD = "abcdefgh";

const char* MQTT_HOST     = "10.236.127.128";
const char* MQTT_TOPIC    = "iot/env";      
const char* DEVICE_ID     = "D01";            
const char* MQTT_USER     = "D01";
const char* MQTT_PASSWORD = "D01_IOT_TLS_2026!@";

#if ENABLE_TLS
  const int MQTT_PORT = 8883; 
#else
  const int MQTT_PORT = 1883; 
#endif

const uint8_t HMAC_KEY[32] = {
  0x4A, 0x8F, 0x3C, 0xD2, 0x71, 0xB5, 0xE9, 0x06,
  0xAF, 0x2D, 0x85, 0x1C, 0x93, 0x60, 0x4E, 0xF7,
  0x38, 0xBA, 0x5D, 0x29, 0xC1, 0x7E, 0x04, 0x9B,
  0xD6, 0x52, 0x1F, 0x87, 0xE3, 0x40, 0xAC, 0x6B
};

#define DHT_PIN   4       
#define DHT_TYPE  DHT11   

#define MQ2_PIN   34       

#define TEMP_WARNING   35
#define TEMP_DANGER    40

#define HUM_LOW        20
#define HUM_HIGH       90

#define GAS_WARNING    1500
#define GAS_DANGER     2500

#define LUX_LOW        60
#define LUX_HIGH       10000

#define SEND_INTERVAL_MS 5000

unsigned long lastMQTTConnectTime = 0; 
#define MQTT_RECONNECT_INTERVAL_MS 10000

unsigned long lastWiFiReconnectTime = 0;
#define WIFI_RECONNECT_INTERVAL_MS 10000 

//  CHUNG CHÍ CA CỦA MQTT BROKER
#if ENABLE_TLS
const char* CA_CERT = R"EOF(
-----BEGIN CERTIFICATE-----
MIIDgzCCAmugAwIBAgIUJmr9ODHHcyskn7ZOfJebAdNBD54wDQYJKoZIhvcNAQEL
BQAwUTELMAkGA1UEBhMCVk4xDjAMBgNVBAgMBUhhbm9pMQ4wDAYDVQQHDAVIYW5v
aTEPMA0GA1UECgwGSW9UTGFiMREwDwYDVQQDDAhFbWJlZGRlZDAeFw0yNjA1MjAx
NTA5MTBaFw0yNzA1MjAxNTA5MTBaMFExCzAJBgNVBAYTAlZOMQ4wDAYDVQQIDAVI
YW5vaTEOMAwGA1UEBwwFSGFub2kxDzANBgNVBAoMBklvVExhYjERMA8GA1UEAwwI
RW1iZWRkZWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCh0l23O3iw
RXlOBMnDbGNvtDdal2yZXof5R5hX4NFRSOp4t3uWMKovezeO7KbuLaUsY8thPItX
4vZ43lDCbW5IapRfrgK+Jiine+MyslT+h+z0Jk8HHDpfBK+tahlqOOARG/ZyZ2Lt
iLLkXInrekrTNsLgDyC8v6c2sRCm2gE8cW7BzsMR8NmL9HTkpbzQiF9lyOimOyZD
UztanNWbAguTqmwNLFR8KcyrTKkG8HXCW9qsjE+u/HiHSQHuA15p0IEHQtLHOMAG
y8g+Y0tDFgYI5gTEGL8OgWJ4yCrtJtAd/A0BtWgpOCBFuYyE7FjcE1S4UKDWujP8
2sjySM/Ae+5JAgMBAAGjUzBRMB0GA1UdDgQWBBTAWGUMhi/Cq9t3rzHpCgJQ7U7D
2jAfBgNVHSMEGDAWgBTAWGUMhi/Cq9t3rzHpCgJQ7U7D2jAPBgNVHRMBAf8EBTAD
AQH/MA0GCSqGSIb3DQEBCwUAA4IBAQALgBlMgJmC7/gUL4rjKhVm5hnpbvql/WXZ
tOkgd8axinoCBL4GTDsIw1Ayt7J6SeA4EGbKNXytF4Z2bBoj17y3nsovTjCXbl0z
2zHKyGosyNI+Q3oA9oArzh1H2kGOSMSLfdUbhOZaGjnHm4k7/e0RGLnaKX/ALpgg
5goRvyZFtZvbmp3z97LPIxx+CbA5x2UEu4kIISb1KLNVdLNEydFt+R7yazRi7Iob
iRX+QRkAIJSYrQ9mD3zaOArP4Z5y5Hv7W9WSqXxeDhU3x2yUVlixtxonRSJmTqTU
XEvCVi0Qlyt1S+QGBimgwjKOrhmD8DrMZIDBOIpOp98r8nxHqLA2
-----END CERTIFICATE-----
)EOF";

const char* CLIENT_CERT = R"EOF(
-----BEGIN CERTIFICATE-----
MIIDLzCCAhegAwIBAgIULj/wgY54TUzNB+ofdoR+MteiU+0wDQYJKoZIhvcNAQEL
BQAwUTELMAkGA1UEBhMCVk4xDjAMBgNVBAgMBUhhbm9pMQ4wDAYDVQQHDAVIYW5v
aTEPMA0GA1UECgwGSW9UTGFiMREwDwYDVQQDDAhFbWJlZGRlZDAeFw0yNjA2MzAx
MDM1NTZaFw0yNzA2MzAxMDM1NTZaMA4xDDAKBgNVBAMMA0QwMTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAOUTZzOHcaK6PDRtY5YUwvFWZb3rb/aHxFhB
iAbbVpOabUBiRH283gGrXxpkHBDmBsUncC0nm9goKAv1Kbh55w5e9/iDVdPD9R+W
0chADiXK796oXGL7MqjXhid9960R1MAR8nb+9MK1bN7nsvyHUbNgK4pr58I14mSA
y1lR4bQfYZCqGlnRFqZWSVAyvXFzlxEnQn7yRvU577D+znv2c2R5aHZp9GqFGn2t
eh3SXp+/lSAQyyDxsNc5DrTl9/6UCfZr4Q44B8hOD/sS8WJbNy5odCRVK2FKTVsZ
bG3h7DjKZnIKRFkqbxmiVcdC6vXJ/Vde+2sbpQth2A6TWj3IW0cCAwEAAaNCMEAw
HQYDVR0OBBYEFApW0qk4mYI+0HFhyqfhXxkb/HvkMB8GA1UdIwQYMBaAFMBYZQyG
L8Kr23evMekKAlDtTsPaMA0GCSqGSIb3DQEBCwUAA4IBAQByJlaGTXjcdtUeOZ/X
GnvVPGgBwzNsgx0pAVh/H424mYCwaZGp2Z/2W6bET/ytrFkRkuQ0PebgiZanSEQ7
uIRf2TwPxaAKIQ6qhA91xKzo3E55oIW7dyhizP4eDqWj3Z7xu+lCaTxlVlpB2wZl
pc6EBjxyzCkVdrZUn84p4HAttc+8xcRphamATHXjjOf8tcRX/4vj31yfoODeK9mo
SXykNyCs4lVdZWhxzo7kLEzFS5hkuK1scLdspNH7kWq45Sq49/RusIE5x1rhJOj6
bTzgETYAAOqrPhAENeBXwg2K8bLC/y9cHt35LmHTmcYyXaARNl3RUqIvyvIy+DQ1
5Vos
-----END CERTIFICATE-----
)EOF";

const char* CLIENT_KEY = R"EOF(
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDlE2czh3Giujw0
bWOWFMLxVmW962/2h8RYQYgG21aTmm1AYkR9vN4Bq18aZBwQ5gbFJ3AtJ5vYKCgL
9Sm4eecOXvf4g1XTw/UfltHIQA4lyu/eqFxi+zKo14YnffetEdTAEfJ2/vTCtWze
57L8h1GzYCuKa+fCNeJkgMtZUeG0H2GQqhpZ0RamVklQMr1xc5cRJ0J+8kb1Oe+w
/s579nNkeWh2afRqhRp9rXod0l6fv5UgEMsg8bDXOQ605ff+lAn2a+EOOAfITg/7
EvFiWzcuaHQkVSthSk1bGWxt4ew4ymZyCkRZKm8ZolXHQur1yf1XXvtrG6ULYdgO
k1o9yFtHAgMBAAECggEAciZgk1dng2jdTlzCNsvitqNQcLrNIKLX7wi8sXoEIupd
jatKKQP/9wIAEqUXLT6K2hzEc+Pcb3LXPdotr40jW9BsLcy4bJ2l3NdpcymkQyXk
sOXhn7tAK822PqCxVm9fvlRTKAP1UL9aYJtB4D/IMSP3nnMV2nvCdEWPz1MTrw7Q
jBcPN/KcJwSyRKmmPxvWrtb9AoZvKgbSsUFOC+xmxK6zLNawZ6V4Vg4r7BdrZPPi
FdwJVodf3wx1PJo2YUDlVbgMQ8rj08B8THhX/MV/M/YoxT49S/7f7hVS4GNq87dN
PDDcvKN6CDlevxcNa2YHstghWwMAhIzes8b8pJEQ/QKBgQD+Nz5wWO1BITZk8j6V
TLQ7hP2JbOrwKEGYzD3U3dS8oE65e09yLEMUxkSAUC9mSmXu89UpnQdRjfIBU52x
k0j097mh/M+GXrmgOgvVcdCqkvhjJuGYQunf1zUglOyqklHZw64ySKqI9FgWvTXh
WFnLHanTLs1jC48mFVI04YVGuwKBgQDmrv1SIQPpArGYk87QFjaj8EzTrPg1XC3+
xobi3gj8CMv+hbFsCWqn1E7oWAnEGoRN64+Okm56h/N/rdV2VrrHPlhtj91dDeis
X3KVzoQ1LwzFzr47fUH+ZAtLmFDdDVvdA7mR7OC4Y2MMgoJt8CSx2iL+qCCfi3l6
cwbkOu3i5QKBgQDWddR/AwZkg5hX4OVbHrKN48vgO7qXj96HAQbIpbvqxXKkl5qW
PzD4PatcdEkIiosj4yBZUtfxvUYESH4oaJCL2NEKDzUjrpX6zf1du/7FZ+eT/iEj
So/y/qMbMYfW/kl+5M34LcVwdHI7/LOPv/FAoW27cyhh/kZtYl9PrVG6MQKBgHFC
f2vAe/v+b5XbFFKEZYVuKTpQlXkVbhvF+1oN69latFWd7HN/2BbYnXlkKD9ZSZY8
TrqQWJ/eegY5IjI8+O10RdRdKzFR7+gZ4Nd+ktjN5faEwE/S+wDcu9L80M8HjQ/h
kU39QIQnf+0XctRpcIrF8CKaB5Jt11HwgfSynjOlAoGAOha1fiEdzVj4tXdGm4iZ
nvxAEIYdCzsNlh2zAaqAJVMisA4Ti87uoDs8PFH55cGryb1bs5yfBIEY8jhXCRfF
BnVk1vR8SqRXvKuo46JWUSahSAlNFKWKBxUKJPG9MdT/xRcPW+eJIrWOsgV0iMZN
qIVbZXz4yNpJ+Bq9ZGH7iqo=
-----END PRIVATE KEY-----
)EOF";
#endif

DHT    dht(DHT_PIN, DHT_TYPE);
BH1750 lightMeter;

#if ENABLE_TLS
  WiFiClientSecure wifiClientSecure;
  PubSubClient     mqttClient(wifiClientSecure); 
#else
  WiFiClient       wifiClientNormal;
  PubSubClient     mqttClient(wifiClientNormal); 
#endif

unsigned long lastSendTime = 0;

#if ENABLE_HMAC
String computeHMAC(const String& message) {
  uint8_t result[32]; 
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
  
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1); 
  
  mbedtls_md_hmac_starts(&ctx, HMAC_KEY, sizeof(HMAC_KEY));
  mbedtls_md_hmac_update(&ctx, (const unsigned char *)message.c_str(), message.length());
  mbedtls_md_hmac_finish(&ctx, result);
  mbedtls_md_free(&ctx);

  String hex = "";
  hex.reserve(64);
  for (int i = 0; i < 32; i++) {
    if (result[i] < 0x10) hex += "0";
    hex += String(result[i], HEX);
  }
  return hex;
}
#endif

float readMQ2_Voltage() {
  const int SAMPLES = 10;
  int readings[SAMPLES];
  for (int i = 0; i < SAMPLES; i++) {
    readings[i] = analogRead(MQ2_PIN);
    delay(5);
  }
  for (int i = 0; i < SAMPLES - 1; i++) {
    for (int j = i + 1; j < SAMPLES; j++) {
      if (readings[i] > readings[j]) {
        int temp = readings[i];
        readings[i] = readings[j];
        readings[j] = temp;
      }
    }
  }
  int total = 0;
  for (int i = 2; i < SAMPLES - 2; i++) {
    total += readings[i];
  }
  int adcRaw = total / (SAMPLES - 4);

  if (adcRaw < 1) return 0.0;
  if (adcRaw > 4095) return 3300.0;
  
  float Vout = 0.000000000030 * pow(adcRaw, 4) 
             - 0.000000382000 * pow(adcRaw, 3) 
             + 0.000015500000 * pow(adcRaw, 2) 
             + 0.775300000000 * adcRaw 
             + 152.0;
             
  return Vout; 
}

enum AlertLevel
{
  NORMAL  = 0,
  WARNING = 1,
  DANGER  = 2
};

void readAndPublish() {
  float temp = dht.readTemperature();  
  float hum  = dht.readHumidity();     

  if (isnan(temp) || isnan(hum)) {
    Serial.println("[DHT11] Loi doc cam bien! Kiem tra ket noi GPIO.");
    return;
  }

  float gasVoltage = readMQ2_Voltage();
  int alertLevel = NORMAL;
  bool isGasAlert = false; 

  if(temp >= TEMP_WARNING) alertLevel = WARNING;
  if(temp >= TEMP_DANGER) alertLevel = DANGER;

  if(hum < HUM_LOW || hum > HUM_HIGH) {
      if(alertLevel < WARNING) alertLevel = WARNING;
  }

  if(gasVoltage >= GAS_WARNING) {
      isGasAlert = true;
      if(alertLevel < WARNING) alertLevel = WARNING;
  }
  if(gasVoltage >= GAS_DANGER) {
      alertLevel = DANGER;
  }

  float lux = lightMeter.readLightLevel();
  if(lux < LUX_LOW) {
    if(alertLevel < WARNING) alertLevel = WARNING;
  }

  if (lux < 0) {
    Serial.println("[BH1750] Loi doc cuong do anh sang! Gan mac dinh bang 0.");
    lux = 0.0;
  }

  time_t nowTime = time(nullptr);
  unsigned long ts = (unsigned long)nowTime;

  StaticJsonDocument<192> payloadDoc;
  payloadDoc["d"]    = DEVICE_ID;
  payloadDoc["temp"] = serialized(String(temp, 1));  
  payloadDoc["hum"]  = serialized(String(hum, 0));   
  payloadDoc["gas"]  = (int)gasVoltage;
  payloadDoc["lux"]  = serialized(String(lux, 1));
  payloadDoc["ale"]  = alertLevel;
  payloadDoc["ts"]   = ts; 

  String corePayload;
  serializeJson(payloadDoc, corePayload);
  String finalMessage;

  #if ENABLE_HMAC
    unsigned long hmacStart = micros();
    String hmacValue = computeHMAC(corePayload);
    unsigned long hmacEnd = micros();
    Serial.printf("[PERF] HMAC Time = %lu us\n", hmacEnd - hmacStart);

    StaticJsonDocument<320> finalDoc; 
    finalDoc["data"] = corePayload;  
    finalDoc["hmac"] = hmacValue;            
    serializeJson(finalDoc, finalMessage);
  #else
    finalMessage = corePayload;
  #endif
  
  Serial.printf("[PERF] Kich thuoc payload goc = %d byte\n", corePayload.length());
  Serial.printf("[PERF] Kich thuoc goi tin gui di = %d byte\n", finalMessage.length());

  struct tm* ti = localtime(&nowTime);
  char timeStr[32];
  strftime(timeStr, sizeof(timeStr), "%H:%M:%S %d/%m/%y", ti);
  
  Serial.println("\n-------------------------------------------");
  Serial.println("[CAM BIEN] Thong so do duoc tai cho:");
  Serial.println("  Thoi gian: " + String(timeStr));
  Serial.println("  Nhiet do : " + String(temp, 1) + " do C");
  Serial.println("  Do am    : " + String(hum, 0) + " %");
  Serial.println("  Khi Gas  : " + String(gasVoltage, 0) + " mV" + (isGasAlert ? " [CANH BAO!]" : " [Binh thuong]"));
  Serial.println("  Anh sang : " + String(lux, 1) + " lx");

  String alertText = "NORMAL";
  if(alertLevel == WARNING)  alertText = "WARNING";
  if(alertLevel == DANGER)   alertText = "DANGER";
  Serial.println("  Muc canh bao : " + alertText);
  
  if (mqttClient.connected()) {
    if (mqttClient.publish(MQTT_TOPIC, finalMessage.c_str())) {
      #if ENABLE_HMAC
        Serial.println("Chu ky HMAC: " + hmacValue);
      #endif
    } else {
      Serial.println("[ERR] Gui MQTT that bai!");
    }
  } else {
    Serial.println("[ERR] MQTT dang mat ket noi!");
  }
}

void connectWiFi() {
  Serial.print("\n[WiFi] Dang ket noi toi: " + String(WIFI_SSID));
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 20) {
    delay(500);
    Serial.print(".");
    attempts++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\n[WiFi] Thanh cong! IP: " + WiFi.localIP().toString());
    
    configTime(7 * 3600, 0, "pool.ntp.org", "time.nist.gov");
    Serial.print("[NTP] Dang dong bo thoi gian thuc");
    
    while (time(nullptr) < 1000000000) {
      delay(500);
      Serial.print(".");
    }
    Serial.println(" -> Dong bo XONG!");

    #if ENABLE_TLS
      uint32_t heapBeforeCert = ESP.getFreeHeap();
      wifiClientSecure.setCACert(CA_CERT);
      wifiClientSecure.setCertificate(CLIENT_CERT);
      wifiClientSecure.setPrivateKey(CLIENT_KEY);
      uint32_t heapAfterCert = ESP.getFreeHeap();                 
      Serial.printf("[PERF] Heap TLS cert chiem dung = %d bytes\n", heapBeforeCert - heapAfterCert); 
      Serial.printf("[PERF] Heap sau khi nap TLS = %u bytes\n", heapAfterCert); 
      Serial.println("[TLS] Da nap chung chi CA hop le.");
    #endif
  } else {
    Serial.println("\n[WiFi] That bai. Khoi dong lai chip...");
    ESP.restart();
  }
}

bool connectMQTT() {
  Serial.printf("[PERF] Free Heap = %u bytes\n", ESP.getFreeHeap());
  if (mqttClient.connected()) return true;

  mqttClient.setServer(MQTT_HOST, MQTT_PORT);
  mqttClient.setBufferSize(512);

  Serial.printf("[MQTT] Dang thu ket noi toi Cong %d...", MQTT_PORT);
  String clientId = "ESP32-" + String(DEVICE_ID);

  unsigned long tlsStart = millis();
  bool ok = (strlen(MQTT_USER) > 0)
      ? mqttClient.connect(clientId.c_str(), MQTT_USER, MQTT_PASSWORD)
      : mqttClient.connect(clientId.c_str());
  unsigned long tlsEnd = millis();

  #if ENABLE_TLS
  Serial.printf("[PERF] TLS Handshake = %lu ms\n", tlsEnd - tlsStart);
  #endif

  if (ok) {
    Serial.println(" Thanh cong!");
    return true;
  } else {
    Serial.println(" That bai (rc=" + String(mqttClient.state()) + ")");
    return false;
  }
}

void setup() {
  Serial.begin(115200);
  Serial.printf("[PERF] Heap dau tien (baseline) = %u bytes\n", ESP.getFreeHeap());
  dht.begin();
  Wire.begin(21, 22); 
  if (lightMeter.begin(BH1750::CONTINUOUS_HIGH_RES_MODE)) {
    Serial.println("[BH1750] Cam bien anh sang san sang!");
  } else {
    Serial.println("[BH1750] Kiem tra ket noi day SCL/SDA phan cung!");
  }
  analogReadResolution(12);
  analogSetAttenuation(ADC_11db);
  Serial.println("[HT] Dang trong thoi gian say MQ2 (30s)...");
  delay(30000);
  connectWiFi();
  connectMQTT();
  Serial.printf("\n[HT] Ss. Che do: TLS [%s] | HMAC [%s]\n\n",ENABLE_TLS ? "ON" : "OFF", ENABLE_HMAC ? "ON" : "OFF");
}
    
void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    unsigned long currentWiFiMillis = millis();

    if (currentWiFiMillis - lastWiFiReconnectTime >= WIFI_RECONNECT_INTERVAL_MS) {
      lastWiFiReconnectTime = currentWiFiMillis;
      Serial.println("\n[WiFi] Mat ket noi! Dang yeu cau tu dong ket noi lai...");
      WiFi.disconnect();
      WiFi.begin(WIFI_SSID, WIFI_PASSWORD); 
    }
    return; 
  }

  if (mqttClient.connected()) {
    mqttClient.loop();
  } else {
    unsigned long currentMillis = millis();
    if (currentMillis - lastMQTTConnectTime >= MQTT_RECONNECT_INTERVAL_MS) {
      lastMQTTConnectTime = currentMillis; 
      connectMQTT(); 
    }
  }

  unsigned long now = millis();
  if (now - lastSendTime >= SEND_INTERVAL_MS) {
    lastSendTime = now; 
    readAndPublish();
  }
}
