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

// ============================================================================
//  CẤU HÌNH BẬT / TẮT BẢO MẬT 
// ============================================================================
#define ENABLE_TLS   1   
#define ENABLE_HMAC  1   

// --- Thong tin WiFi ---
const char* WIFI_SSID     = "Nhóm 30";
const char* WIFI_PASSWORD = "abcdefgh";

// --- Thong tin MQTT Broker ---
const char* MQTT_HOST     = "10.236.127.128";
const char* MQTT_TOPIC    = "iot/env";      
const char* DEVICE_ID     = "D02";            
const char* MQTT_USER     = "D02";
const char* MQTT_PASSWORD = "D02_IOT_TLS_2026!@";

#if ENABLE_TLS
  const int MQTT_PORT = 8883; 
#else
  const int MQTT_PORT = 1883; 
#endif

// --- Khoa bi mat HMAC ---
const uint8_t HMAC_KEY[32] = {
0x3E, 0x53, 0xCF, 0xD5, 0x3F, 0x0B, 0x1D, 0x93,
0x25, 0xD6, 0xB2, 0x7A, 0xF9, 0x49, 0x9C, 0xFE, 
0x6A, 0x4E, 0x91, 0x84, 0xCF, 0x0B, 0x72, 0x98, 
0xD5, 0x5B, 0x8D, 0xFA, 0xC2, 0xF5, 0xF8, 0xD0
};

// --- Cam bien DHT11 ---
#define DHT_PIN   4       
#define DHT_TYPE  DHT11   

// --- Cam bien khi gas MQ2 ---
#define MQ2_PIN   34       

// ================== NGUONG GIAM SAT ==================
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

// Biến quản lý thời gian thử lại kết nối WiFi (Tránh spam)
unsigned long lastWiFiReconnectTime = 0;
#define WIFI_RECONNECT_INTERVAL_MS 10000 

// ============================================================================
//  CHUNG CHÍ CA CỦA MQTT BROKER
// ============================================================================
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
MIIDLzCCAhegAwIBAgIULj/wgY54TUzNB+ofdoR+MteiU+4wDQYJKoZIhvcNAQEL
BQAwUTELMAkGA1UEBhMCVk4xDjAMBgNVBAgMBUhhbm9pMQ4wDAYDVQQHDAVIYW5v
aTEPMA0GA1UECgwGSW9UTGFiMREwDwYDVQQDDAhFbWJlZGRlZDAeFw0yNjA2MzAx
MDM4MjBaFw0yNzA2MzAxMDM4MjBaMA4xDDAKBgNVBAMMA0QwMjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAKPc8XBSQc6vmQCdnreWRzR2KyaKf3W6Dhxo
nr3PaW3w9CEpRkPU4NXZ5hSRdUoaKtfnfUSL/wL8UJPeTgfnOTJEgqEb4r3WfS/O
LATCQz3OkepBrfZ8028qaKUeGqax9DJ77X4yO2dG2jnSAsstHqmgvMynMFBCzN4O
ACz3NiJFKykLdoyVTVZmFQFrWX/OjMHDBbXIQ9qPJYderPtRROW9QO3HlnoaR8Mk
y0h+odI3neUoE0H3r6bs+j7SO+ULWUDuoAuVt8hVZGw6bL1S33dfnNi5Ca3AKON4
oQD1e1FMupnJQ4MuAzjNBVVtMjcZm59m9zUXFnwrWvKNBf9bgicCAwEAAaNCMEAw
HQYDVR0OBBYEFOa19Wt/4X/k+U1OSx6WlCordjIPMB8GA1UdIwQYMBaAFMBYZQyG
L8Kr23evMekKAlDtTsPaMA0GCSqGSIb3DQEBCwUAA4IBAQAku2yHXg0K/ducwRUK
ql2Skbt4DcqWaWUSF0fq2tO3stC7tJSlYvFriaiXyQqET7hYhI2NBZi6++yL80x8
dTa9AycjHuWkL5E7IBe8z0jtZoNtSL+F8blGI3NcLSSKF7HHWZM2l+GOnfzIprH/
Zv46Pz7FUJYiGvnOOIvka/IkwUMSTujff+2XtWkZwEgDhzdRXokqe4ZVHFyh3lP/
JkW9FJdnXCinqOlhWQrMW69OflHpnZEi7ERGGj3XXydfgs4ZIcDbTDEW+p5tiMGt
3raI21xhu/M8trE2Veu+iEwBiVL5DGOrx2C3bVEE38mWwKFrzmrRbkf5pqtk5w66
QXM5
-----END CERTIFICATE-----
)EOF";

const char* CLIENT_KEY = R"EOF(
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCj3PFwUkHOr5kA
nZ63lkc0dismin91ug4caJ69z2lt8PQhKUZD1ODV2eYUkXVKGirX531Ei/8C/FCT
3k4H5zkyRIKhG+K91n0vziwEwkM9zpHqQa32fNNvKmilHhqmsfQye+1+MjtnRto5
0gLLLR6poLzMpzBQQszeDgAs9zYiRSspC3aMlU1WZhUBa1l/zozBwwW1yEPajyWH
Xqz7UUTlvUDtx5Z6GkfDJMtIfqHSN53lKBNB96+m7Po+0jvlC1lA7qALlbfIVWRs
Omy9Ut93X5zYuQmtwCjjeKEA9XtRTLqZyUODLgM4zQVVbTI3GZufZvc1FxZ8K1ry
jQX/W4InAgMBAAECggEAO5Hpz+yHce0SUU/70D/4mNDQtQ0qcxD1akx6UQSjDk3H
YnrPyX8NUZEKfLW4jvzeUGkeeBnw1hQF8wuhEGx1tZmEZ69siZj9H7Dy/bPloAWF
tES2SmJstwAS1NwR0kHlRakZ2IPIZq4yTUzUqSo4+G+v0zKAdN0j/yHV3ILukhxA
Ftagtpo4TiPCcHaip/UCqCWN8xPVzSNNGIrm8xYsg263Ha3ylQOShgtYLS+0UC8t
F3pZFu+umekLBELfj0WKZ7Bxa65JVWQC+Yczj+VmDGTv6x7z9NjUdMSOGIFS8r6d
bw2d1ZAg9JykglfTxq7ktBejFzGhGahj1j+u6faQ6QKBgQDWajUlkKYgYOsT2cId
RcIblowsh5LVlkxIp2hQXk53zGSmiDhCQYCiwu5yJ5DhppOAP9va1QOPn+PpXqwt
0/dgp3pVrFv9RdZ31x6J20kG/g3G0jyws/Z9LW6996FM3VICHU6NOTY0fbgjri1v
hueQ1abdOm1+X5yeowzxALVGewKBgQDDpNDXWRrjKITD+GzY1Di/d07lCUUIprz3
da70ssot4jNCH0arGw96tmq9DTO/w2t/UlSrrzA3WTpVJWmGWwjtvpc17EHJg2UJ
FUuKGImgPJmIvx5kbpwhTxGq76ILs/L7eWfd1CN4Pzej6aDO5l1Z5J65uiREUZ82
j3s2eCCZRQKBgHfZzDVgQowMwLpK2Wd1a8fyAg6OBbSgG6ns8bEi1ee+92/i6teW
N6pDHffvR9vqOb7RczpCIYhxznrPMZ04Q6niU8551r2fAP/h3i8exRZEgjzlnYkE
Pz6/W4ySU7ZcbA/Eg/kKxtLWh0xiewFBPkVGN8yncTbXiPtflsdMJwfrAoGBAMNs
Q2uIRvI2y/9Qi7E+svyVuUnQq5NLsh/g/oTQfmG8vATFZvqNSjYCNrZmlJVtJ1iD
ra3cjWYMC9d3SmP5VP7dzP8A4mnehLLBAbaMchSL07UjasFZNz2SVIyRVyUnd4O4
LocHWvLG+tYRDR7+PqsHUYElrQpNGaMPST0MW0udAoGANOCUnLWMKgaHwCGZjGwq
oRXpW/dSXG1ws42cYM4C678MT35jE7oRclhn3yd6qwpQkkwWi8leV1C/JYfwyCbZ
1qS+vCoyOFGMPia1X8AwD+qfUM5+lPJSl1XVpiiSFz5xOs3EB5tOpYY087dtOVOZ
Y+6gqdmNat10U7I6x6bVoAA=
-----END PRIVATE KEY-----
)EOF";
#endif

// ============================================================================
//  KHỞI TẠO ĐỐI TƯỢNG
// ============================================================================
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

// ============================================================================
//  computeHMAC()
// ============================================================================
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

// ============================================================================
//  readMQ2_Voltage()
// ============================================================================
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

  // ===== NHIET DO =====
  if(temp >= TEMP_WARNING) alertLevel = WARNING;
  if(temp >= TEMP_DANGER) alertLevel = DANGER;

  // ===== DO AM =====
  if(hum < HUM_LOW || hum > HUM_HIGH) {
      if(alertLevel < WARNING) alertLevel = WARNING;
  }

  // ===== GAS =====
  if(gasVoltage >= GAS_WARNING) {
      isGasAlert = true;
      if(alertLevel < WARNING) alertLevel = WARNING;
  }
  if(gasVoltage >= GAS_DANGER) {
      alertLevel = DANGER;
  }

  // --- Doc cuong do anh sang ---
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

// ============================================================
//  connectWiFi() & Dong bo gio NTP
// ============================================================
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
      wifiClientSecure.setCACert(CA_CERT);
      wifiClientSecure.setCertificate(CLIENT_CERT);
      wifiClientSecure.setPrivateKey(CLIENT_KEY);
      Serial.printf("[PERF] Heap Before MQTT = %u bytes\n", ESP.getFreeHeap());
      Serial.println("[TLS] Da nap chung chi CA hop le.");
    #endif
  } else {
    Serial.println("\n[WiFi] That bai. Khoi dong lai chip...");
    ESP.restart();
  }
}

// ============================================================
//  connectMQTT()
// ============================================================
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
  // --- KHU VỰC SỬA ĐỔI CHÍNH: XỬ LÝ MẤT KẾT NỐI WIFI ---
  if (WiFi.status() != WL_CONNECTED) {
    unsigned long currentWiFiMillis = millis();
    // Thay vì gọi WiFi.begin() liên tục, chỉ gọi lại sau mỗi 10 giây (WIFI_RECONNECT_INTERVAL_MS)
    if (currentWiFiMillis - lastWiFiReconnectTime >= WIFI_RECONNECT_INTERVAL_MS) {
      lastWiFiReconnectTime = currentWiFiMillis;
      Serial.println("\n[WiFi] Mat ket noi! Dang yeu cau tu dong ket noi lai...");
      WiFi.disconnect(); // Ngắt hẳn trạng thái cũ 
      WiFi.begin(WIFI_SSID, WIFI_PASSWORD); // Phát lệnh kết nối và để ESP32 tự xử lý ngầm
    }
    return; // Thoát loop ngay, không chạy tiếp các lệnh MQTT phía dưới khi chưa có mạng
  }

  // --- XỬ LÝ MQTT ---
  if (mqttClient.connected()) {
    mqttClient.loop();
  } else {
    unsigned long currentMillis = millis();
    if (currentMillis - lastMQTTConnectTime >= MQTT_RECONNECT_INTERVAL_MS) {
      lastMQTTConnectTime = currentMillis; 
      connectMQTT(); 
    }
  }

  // --- HẸN GIỜ ĐỌC VÀ GỬI DỮ LIỆU ---
  unsigned long now = millis();
  if (now - lastSendTime >= SEND_INTERVAL_MS) {
    lastSendTime = now; 
    readAndPublish();
  }
}