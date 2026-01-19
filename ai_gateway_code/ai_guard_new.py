import time
import pandas as pd
import numpy as np
import joblib
import os
import sys
import warnings
import csv
from datetime import datetime

# Disable warnings for cleaner output
warnings.filterwarnings("ignore")
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' 

from tensorflow.keras.models import load_model

# ==========================================
# ⚙️ SYSTEM CONFIGURATION
# ==========================================
ZEEK_LOG_PATH = '/home/okai/zeek_demo/conn.log' 
MODEL_DIR = './model_assets/'
MALWARE_LOG_FILE = 'malware_detected.csv' # File to save malicious logs

# 9 Features for the new model (Must match training order)
FEATURE_ORDER = [
    'id.orig_p', 'id.resp_p', 'proto', 'conn_state', 'history', 
    'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes'
]

# ==========================================
# 📥 LOAD ASSETS
# ==========================================
print(f"⏳ Initializing AI Gateway (English Version)...")

try:
    # 1. Load NEW model files
    model = load_model(os.path.join(MODEL_DIR, 'iot_ddos_detection_model.h5'))
    scaler = joblib.load(os.path.join(MODEL_DIR, 'standard_scaler.pkl'))
    label_encoder = joblib.load(os.path.join(MODEL_DIR, 'label_encoder.pkl')) 

    # 2. Load OLD encoder files (for Zeek log translation)
    encoders = {
        'proto': joblib.load(os.path.join(MODEL_DIR, 'categorical_label_encoder_proto.pkl')),
        'conn_state': joblib.load(os.path.join(MODEL_DIR, 'categorical_label_encoder_conn_state.pkl')),
        'history': joblib.load(os.path.join(MODEL_DIR, 'categorical_label_encoder_history.pkl'))
    }
    print("✅ System Loaded Successfully!")

except Exception as e:
    print(f"\n❌ INITIALIZATION ERROR: {e}")
    sys.exit(1)

# ==========================================
# 📝 LOGGING FUNCTION
# ==========================================
def log_malware_to_csv(timestamp, src_ip, src_port, dst_ip, dst_port, proto, state, conf):
    """Save malicious traffic details to CSV file"""
    file_exists = os.path.isfile(MALWARE_LOG_FILE)
    
    with open(MALWARE_LOG_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        # Write header if file is new
        if not file_exists:
            writer.writerow(['Timestamp', 'Source_IP', 'Source_Port', 'Dest_IP', 'Dest_Port', 'Protocol', 'State', 'Confidence'])
        
        # Write data
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        writer.writerow([current_time, src_ip, src_port, dst_ip, dst_port, proto, state, f"{conf:.2f}%"])

# ==========================================
# 🧠 PREDICTION LOGIC
# ==========================================
def preprocess_and_predict(log_data):
    try:
        df = pd.DataFrame([log_data])

        # 1. Numeric casting
        numeric_cols = ['id.orig_p', 'id.resp_p', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes']
        for col in numeric_cols:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

        # 2. Encoding categorical data
        for col in ['proto', 'conn_state', 'history']:
            encoder = encoders[col]
            val = str(df[col][0])
            if val in encoder.classes_:
                df[col] = encoder.transform([val])[0]
            else:
                df[col] = 0 

        # 3. Scaling & Predicting
        X = df[FEATURE_ORDER].values
        X_scaled = scaler.transform(X)
        
        pred_probs = model.predict(X_scaled, verbose=0)
        pred_idx = np.argmax(pred_probs)
        pred_label = label_encoder.inverse_transform([pred_idx])[0]
        confidence = np.max(pred_probs) * 100

        return str(pred_label), confidence

    except Exception as e:
        return "Error", 0

# ==========================================
# 🕵️ LOG FOLLOWER
# ==========================================
def follow(file):
    file.seek(0, 2)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

# ==========================================
# 🚀 MAIN LOOP
# ==========================================
print(f"🚀 Gateway is monitoring: {ZEEK_LOG_PATH}")
print(f"📂 Malware logs will be saved to: {MALWARE_LOG_FILE}")
print("... Waiting for traffic ...")

# Stats Counters
total_benign = 0
total_malicious = 0

try:
    logfile = open(ZEEK_LOG_PATH, "r")
    
    headers = ['ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p',
               'proto','service','duration','orig_bytes','resp_bytes',
               'conn_state','local_orig','local_resp','missed_bytes',
               'history','orig_pkts','orig_ip_bytes','resp_pkts','resp_ip_bytes','tunnel_parents']

    col_idx = {name: idx for idx, name in enumerate(headers)}

    for line in follow(logfile):
        if line.startswith('#'): continue 
        
        parts = line.strip().split('\t')
        if len(parts) < 20: continue 

        # Extract Raw Data
        log_data = {}
        try:
            # Features for AI
            log_data['id.orig_p'] = parts[col_idx['id.orig_p']]
            log_data['id.resp_p'] = parts[col_idx['id.resp_p']]
            log_data['proto'] = parts[col_idx['proto']]
            log_data['conn_state'] = parts[col_idx['conn_state']]
            log_data['history'] = parts[col_idx['history']]
            log_data['orig_pkts'] = parts[col_idx['orig_pkts']]
            log_data['orig_ip_bytes'] = parts[col_idx['orig_ip_bytes']]
            log_data['resp_pkts'] = parts[col_idx['resp_pkts']]
            log_data['resp_ip_bytes'] = parts[col_idx['resp_ip_bytes']]
            
            # Metadata for Logging (Not used by AI)
            src_ip = parts[col_idx['id.orig_h']]
            dst_ip = parts[col_idx['id.resp_h']]
            
            # Format display strings
            src_display = f"{src_ip}:{log_data['id.orig_p']}"
            dst_display = f"{dst_ip}:{log_data['id.resp_p']}"

        except IndexError:
            continue

        # --- AI INFERENCE ---
        label, conf = preprocess_and_predict(log_data)

        # --- LOGIC & STATS ---
        label_str = str(label)
        is_safe = False
        
        if label_str == '0' or label_str.lower() == 'benign':
            is_safe = True
            total_benign += 1
            status_tag = "NORMAL"
            color = "\033[92m" # Green
        elif label_str != "Error":
            total_malicious += 1
            status_tag = "ATTACK"
            color = "\033[91m" # Red
            
            # 💾 Save to CSV File
            log_malware_to_csv(parts[0], src_ip, log_data['id.orig_p'], 
                               dst_ip, log_data['id.resp_p'], 
                               log_data['proto'], log_data['conn_state'], conf)
        
        # --- UNIFIED DISPLAY FORMAT ---
        # Format: [STATUS] SRC -> DST | PROTO | STATE | CONFIDENCE | STATS
        if label_str != "Error":
            print(f"{color}● [{status_tag}] {src_display} -> {dst_display} | {log_data['proto'].upper()} | State: {log_data['conn_state']} | Conf: {conf:.1f}% | (Stats: Normal={total_benign}, Attack={total_malicious})\033[0m")

except FileNotFoundError:
    print(f"❌ Error: Log file not found at '{ZEEK_LOG_PATH}'")
except KeyboardInterrupt:
    print("\n🛑 Gateway Stopped.")