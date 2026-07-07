import eventlet
eventlet.monkey_patch()
import json
import hmac
import hashlib
import time
import pymysql
import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion 
from flask import Flask, jsonify, render_template
from flask_socketio import SocketIO
from datetime import datetime

MQTT_HOST = "10.236.127.128"
MQTT_TOPIC = "iot/env"      

ENABLE_TLS = True  
ENABLE_HMAC = True

VALID_DEVICES = ["D01", "D02"]

if ENABLE_TLS:
    MQTT_PORT = 8883
else:
    MQTT_PORT = 1883

DB_HOST = "127.0.0.1"
DB_USER = "root"          
DB_PASS = "MySQL12345@@@"             
DB_NAME = "iot_db"           

HMAC_KEY_1 = bytes([
    0x4A, 0x8F, 0x3C, 0xD2, 0x71, 0xB5, 0xE9, 0x06,
    0xAF, 0x2D, 0x85, 0x1C, 0x93, 0x60, 0x4E, 0xF7,
    0x38, 0xBA, 0x5D, 0x29, 0xC1, 0x7E, 0x04, 0x9B,
    0xD6, 0x52, 0x1F, 0x87, 0xE3, 0x40, 0xAC, 0x6B
])

HMAC_KEY_2 = bytes([
    0x3E, 0x53, 0xCF, 0xD5, 0x3F, 0x0B, 0x1D, 0x93, 
    0x25, 0xD6, 0xB2, 0x7A, 0xF9, 0x49, 0x9C, 0xFE, 
    0x6A, 0x4E, 0x91, 0x84, 0xCF, 0x0B, 0x72, 0x98, 
    0xD5, 0x5B, 0x8D, 0xFA, 0xC2, 0xF5, 0xF8, 0xD0
])

DEVICE_KEYS = {
    "D01": HMAC_KEY_1,
    "D02": HMAC_KEY_2
}

hmac_cache = {}
CACHE_WINDOW_SEC = 30 

def clean_hmac_cache(current_server_ts):
    """Dọn dẹp RAM định kỳ: Xóa các mã HMAC đã lưu quá 30 giây"""
    global hmac_cache
    expired_keys = [k for k, ts in hmac_cache.items() if current_server_ts - ts > CACHE_WINDOW_SEC]
    for k in expired_keys:
        del hmac_cache[k]

app = Flask(__name__)

socketio = SocketIO(
    app, 
    cors_allowed_origins="*",
    async_mode='eventlet',
    logger=True,          
    engineio_logger=True
)

@socketio.on('connect')
def handle_connect(auth):
    print("[🛡️ SECURITY] Có thiết bị/giao diện Web yêu cầu kết nối luồng Realtime.")
    if not auth or auth.get('token') != "SecretWebToken123@@@":
        print("[⚠️ SECURITY] Kết nối WebSocket bị TỪ CHỐI: Token xác thực không khớp!")
        return False 
    print("[🛡️ SECURITY] Kết nối WebSocket được CHẤP NHẬN thành công.")

@app.route('/', methods=['GET'])
def index():
    return render_template('dashboard.html')

@app.route('/api/latest', methods=['GET'])
def get_latest_data():
    try:
        connection = pymysql.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME,
            cursorclass=pymysql.cursors.DictCursor
        )
        with connection.cursor() as cursor:
            sql = """
                SELECT 
                    device_id, temperature, humidity, gas, lux, security_mode, hmac_status, 
                    CASE 
                        WHEN alert_status = 'DANGER' THEN 2
                        WHEN alert_status = 'WARNING' THEN 1
                        ELSE 0
                    END as alert_status,
                    DATE_FORMAT(FROM_UNIXTIME(timestamp), '%H:%i:%s %d/%m/%Y') as created_at,
                    timestamp
                FROM sensor_data 
                ORDER BY id DESC LIMIT 15
            """
            cursor.execute(sql)
            records = cursor.fetchall()
        connection.close()
        return jsonify(records)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def save_log(device_id, event_type, detail):
    try:
        connection = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME)
        with connection.cursor() as cursor:             
            sql = "INSERT INTO system_logs (device_id, event_type, detail) VALUES (%s, %s, %s)"
            cursor.execute(sql, (device_id, event_type, detail))
        connection.commit()
        connection.close()
    except Exception as e:
        print(f"[LOG ERR] Không thể ghi nhật ký hệ thống: {e}")

# ==================== LOGIC XỬ LÝ SỰ KIỆN MQTT ====================
def on_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
        print(f"[OK] Server kết nối vào MQTT Broker thành công (Port: {MQTT_PORT})!")
        client.subscribe(MQTT_TOPIC)
    else:
        print(f"[ERR] Kết nối Broker thất bại, mã lỗi rc = {reason_code}")

def on_message(client, userdata, msg):
    global hmac_cache
    try:
        payload_str = msg.payload.decode("utf-8").strip()
        
        if isinstance(payload_str, dict):
            json_data = payload_str
        else:
            try:
                json_data = json.loads(payload_str)
            except:
                json_data = json.loads(msg.payload)

        data_block = None
        client_hmac = None
        server_ts = int(time.time()) 

        if ENABLE_HMAC:
            if "data" not in json_data or "hmac" not in json_data:
                print("[⚠️ SECURITY]: Gói tin thiếu trường 'data'/'hmac' bắt buộc khi HMAC đang BẬT!")
                return

            data_str = json_data.get("data")
            client_hmac = json_data.get("hmac")

            if isinstance(data_str, dict):
                data_block = data_str
                data_str = json.dumps(data_str, separators=(',', ':'))
            else:
                data_block = json.loads(data_str)
        else:
            data_block = json_data

        dev_id = data_block.get("d", "UNKNOWN")
        if dev_id not in VALID_DEVICES:
            save_log(dev_id, "UNKNOWN_DEVICE", "Thiết bị chưa được đăng ký")
            print(f"\n[⚠️ SECURITY]: Thiết bị không nhận diện được! ID: {dev_id}")
            return 

        if ENABLE_HMAC:
            current_key = DEVICE_KEYS[dev_id]

            server_calc_hmac = hmac.new(current_key, data_str.encode('utf-8'), hashlib.sha256).hexdigest()

            if not hmac.compare_digest(server_calc_hmac, client_hmac):
                save_log(dev_id, "HMAC_FAIL", f"Chữ ký HMAC của {dev_id} không hợp lệ!") 
                print(f"\n[⚠️ SECURITY]: Phát hiện gói tin bị giả mạo từ Node {dev_id}! HMAC FAIL")
                return
            else:
                print(f"\n[VERIFIED - {dev_id}] Kiểm tra tính toàn vẹn gói tin: HMAC OK")

            if client_hmac in hmac_cache:
                save_log(dev_id, "REPLAY_DUPLICATE", f"Phát hiện trùng chuỗi HMAC trong 30s từ {dev_id}")
                print(f"[🚨 REPLAY DETECTED]: Node {dev_id} bị phát lại gói tin trong vòng 30s. HỦY!")
                return
            else:
                hmac_cache[client_hmac] = server_ts
            clean_hmac_cache(server_ts)
        else:
            print(f"\n[INFO - {dev_id}] Chế độ nhận dữ liệu RAW (Không xác thực tầng ứng dụng)")

        client_ts = int(data_block.get("ts", 0))
        temp = float(data_block.get("temp", 0))
        hum  = float(data_block.get("hum", 0))
        gas  = float(data_block.get("gas", 0))
        lux  = float(data_block.get("lux", 0))
        ale  = int(data_block.get("ale", 0))

        if temp < 0 or temp > 50 or hum < 20 or hum > 90 or gas < 0 or lux < 0:
            save_log(dev_id, "SENSOR_ERROR", f"Cảm biến {dev_id} báo giá trị bất thường: T={temp}, H={hum}, Gas={gas}, Lux={lux}")
            return

        if ENABLE_HMAC:
            time_delay = abs(server_ts - client_ts)
            if client_ts > 0 and time_delay > 30:
                save_log(dev_id, "REPLAY_ATTACK", f"Độ trễ thời gian lớn đột biến tại {dev_id}: Delay={time_delay}s")
                print(f"[⚠️ WARNING ANTI-REPLAY]: Phát hiện tấn công phát lại (Replay Attack) trên {dev_id}. HỦY!")
                return

        alert_status = "SAFE"
        if ale == 1:
            alert_status = "WARNING"
        elif ale == 2:
            alert_status = "DANGER"

        sec_mode_str = f"TLS:{'ON' if ENABLE_TLS else 'OFF'}|HMAC:{'ON' if ENABLE_HMAC else 'OFF'}"
        hmac_status_str = "valid" if ENABLE_HMAC else "none"

        connection = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME)
        with connection.cursor() as cursor:
            sql = """
                INSERT INTO sensor_data 
                (device_id, temperature, humidity, gas, lux, alert_status, security_mode, hmac_status, timestamp) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(sql, (
                dev_id, temp, hum, gas, lux, alert_status,
                sec_mode_str, hmac_status_str, client_ts
            ))
        connection.commit()
        connection.close()

        if ale == 1:
            save_log(dev_id, "WARNING", f"Node {dev_id} vượt ngưỡng an toàn nhẹ")
        elif ale == 2:
            save_log(dev_id, "DANGER", f"Node {dev_id} kích hoạt trạng thái NGUY HIỂM!")
            
        print(f"[SUCCESS - {dev_id}] Đã lưu DB: {temp}°C | {hum}% | {gas}mV | Lux: {lux}")

        dt_object = datetime.fromtimestamp(client_ts)
        readable_time = dt_object.strftime("%H:%M:%S %d/%m/%Y")

        web_packet = {
            "device_id": dev_id,
            "temperature": temp,
            "humidity": hum,
            "gas": gas,
            "lux": lux,
            "security_mode": sec_mode_str,
            "hmac_status": hmac_status_str,
            "alert_status": ale,
            "created_at": readable_time,
            "timestamp": client_ts
        }

        socketio.emit('thong_so_moi', web_packet)
        print(f"[⚡ REALTIME]: Đã đẩy dữ liệu đồng bộ thời gian từ {dev_id} lên Dashboard.")

    except Exception as e:
        print(f"[ERR] Lỗi phân tích gói tin: {str(e)}")

if __name__ == '__main__':
    mqtt_client = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION2)
    mqtt_client.on_connect = on_connect
    mqtt_client.on_message = on_message

    if ENABLE_TLS:
        try:
            mqtt_client.tls_set(
                ca_certs="C:/mqtt_tls/ca.crt", 
                certfile="C:/mqtt_tls/server.crt", 
                keyfile="C:/mqtt_tls/server.key"
            )
            print("[TLS] Xác thực mTLS hai chiều (MQTTS - Cổng 8883) đã sẵn sàng.")
        except Exception as e:
            print(f"[TLS ERR] Lỗi đường dẫn hoặc định dạng chứng chỉ số: {str(e)}")
    else:
        print("[TLS] Chế độ KHÔNG bảo mật: kết nối MQTT RAW (Cổng 1883), không có mã hóa/xác thực chứng chỉ.")

    mqtt_client.username_pw_set("python_server", "server.py")

    mqtt_client.connect(MQTT_HOST, MQTT_PORT, 60)
    mqtt_client.loop_start() 
    print("[MQTT] Luồng thu thập MQTT chạy nền thành công.")

    if ENABLE_TLS:
        cert_path = "C:/mqtt_tls/server.crt"
        key_path  = "C:/mqtt_tls/server.key"

        print(f"[SERVER] Web Dashboard đang mở tại địa chỉ: https://localhost:5000")

        import eventlet.wsgi

        listener = eventlet.listen(('0.0.0.0', 5000))
        ssl_listener = eventlet.wrap_ssl(
            listener,
            certfile=cert_path,
            keyfile=key_path,
            server_side=True
        )

        eventlet.wsgi.server(ssl_listener, app)
    else:
        print(f"[SERVER] Web Dashboard đang mở tại địa chỉ: http://localhost:5000")

        import eventlet.wsgi

        listener = eventlet.listen(('0.0.0.0', 5000))
        eventlet.wsgi.server(listener, app)
