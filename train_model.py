import pandas as pd
import numpy as np
import glob
import json
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import warnings
warnings.filterwarnings('ignore')

# ─────────────────────────────────────────────
# CONFIG — change this path to your CSVs folder
# ─────────────────────────────────────────────
DATASET_PATH = "./CICIDS2017/*.csv"   # e.g. "/data/CICIDS2017/*.csv"
OUTPUT_DIR   = "./model_artifacts"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ─────────────────────────────────────────────
# STEP 1: Load all CSVs
# ─────────────────────────────────────────────
print("[1/6] Loading CSVs...")
files = glob.glob(DATASET_PATH)
if not files:
    raise FileNotFoundError(f"No CSVs found at {DATASET_PATH}")

df = pd.concat([pd.read_csv(f, low_memory=False) for f in files], ignore_index=True)
print(f"    Loaded {len(df):,} rows from {len(files)} files")

# ─────────────────────────────────────────────
# STEP 2: Clean column names
# ─────────────────────────────────────────────
df.columns = df.columns.str.strip()
print(f"    Columns: {list(df.columns[:5])}...")

# ─────────────────────────────────────────────
# STEP 3: Select 18 reliable real-time-friendly features
# These match what CICFlowMeter produces in real-time
# ─────────────────────────────────────────────
FEATURES = [
    'Destination Port',
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Fwd Packet Length Max',
    'Fwd Packet Length Min',
    'Fwd Packet Length Mean',
    'Bwd Packet Length Max',
    'Bwd Packet Length Min',
    'Bwd Packet Length Mean',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Fwd IAT Mean',
    'Bwd IAT Mean',
    'PSH Flag Count',
    'SYN Flag Count',
    'ACK Flag Count',
    'Packet Length Mean',
]
LABEL_COL = 'Label'

# Drop missing features
available = [f for f in FEATURES if f in df.columns]
missing   = [f for f in FEATURES if f not in df.columns]
if missing:
    print(f"    WARNING: Missing features (will skip): {missing}")
FEATURES = available

df = df[FEATURES + [LABEL_COL]].copy()

# ─────────────────────────────────────────────
# STEP 4: Clean data
# ─────────────────────────────────────────────
print("[2/6] Cleaning data...")
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# Convert all features to numeric
for col in FEATURES:
    df[col] = pd.to_numeric(df[col], errors='coerce')
df.dropna(inplace=True)
print(f"    Clean rows: {len(df):,}")

# ─────────────────────────────────────────────
# STEP 5: Encode labels
# ─────────────────────────────────────────────
print("[3/6] Encoding labels...")
df[LABEL_COL] = df[LABEL_COL].str.strip()
print(f"    Attack types: {df[LABEL_COL].value_counts().to_dict()}")

le = LabelEncoder()
df['label_encoded'] = le.fit_transform(df[LABEL_COL])
print(f"    Classes: {list(le.classes_)}")

# ─────────────────────────────────────────────
# STEP 6: Balance dataset (downsample BENIGN)
# BENIGN dominates — causes model to always predict BENIGN
# ─────────────────────────────────────────────
print("[4/6] Balancing dataset...")
benign  = df[df[LABEL_COL] == 'BENIGN']
attacks = df[df[LABEL_COL] != 'BENIGN']

# Cap BENIGN to 3x the attack count
max_benign = min(len(benign), len(attacks) * 3)
benign_sample = benign.sample(n=max_benign, random_state=42)
df_balanced = pd.concat([benign_sample, attacks], ignore_index=True)
df_balanced = df_balanced.sample(frac=1, random_state=42).reset_index(drop=True)
print(f"    Balanced: {len(df_balanced):,} rows")

X = df_balanced[FEATURES]
y = df_balanced['label_encoded']

# ─────────────────────────────────────────────
# STEP 7: Scale + Train
# ─────────────────────────────────────────────
print("[5/6] Training model...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled  = scaler.transform(X_test)

model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    n_jobs=-1,
    random_state=42,
    class_weight='balanced'   # handles any remaining imbalance
)
model.fit(X_train_scaled, y_train)

# ─────────────────────────────────────────────
# STEP 8: Evaluate
# ─────────────────────────────────────────────
print("[6/6] Evaluating...")
y_pred = model.predict(X_test_scaled)
print("\n── Classification Report ──")
print(classification_report(y_test, y_pred, target_names=le.classes_))

# ─────────────────────────────────────────────
# STEP 9: Save artifacts
# ─────────────────────────────────────────────
print("\nSaving artifacts...")
pickle.dump(model,  open(f"{OUTPUT_DIR}/model.pkl",  "wb"))
pickle.dump(scaler, open(f"{OUTPUT_DIR}/scaler.pkl", "wb"))
pickle.dump(le,     open(f"{OUTPUT_DIR}/label_encoder.pkl", "wb"))
with open(f"{OUTPUT_DIR}/features.json", "w") as f:
    json.dump(FEATURES, f, indent=2)

print(f"""
✅ Done! Saved to {OUTPUT_DIR}/
    model.pkl           → RandomForest model
    scaler.pkl          → StandardScaler (use on real-time data)
    label_encoder.pkl   → label ↔ class name mapping
    features.json       → exact feature order (critical for real-time)
""")