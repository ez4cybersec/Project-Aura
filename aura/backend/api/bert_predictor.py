import os
# Force pure python protobuf to avoid C++ conflicts
os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"

import torch
from transformers import BertTokenizer, BertForSequenceClassification
import urllib.parse

# ==========================================
# 1. SMART PATH FINDER (Updated for .safetensors)
# ==========================================

def find_model_path():
    """
    Recursively searches for 'model.safetensors' inside backend/models/
    Returns the folder path containing the model file.
    """
    # Start at .../backend/api/
    current_dir = os.path.dirname(os.path.abspath(__file__)) 
    # Go up to .../backend/models/
    search_root = os.path.normpath(os.path.join(current_dir, '..', 'models'))
    
    print(f"🔍 [BERT] Searching for model files in: {search_root}...")

    if not os.path.exists(search_root):
        print(f"❌ [BERT] Error: The directory {search_root} does not exist.")
        return None

    # Walk through all subfolders
    for root, dirs, files in os.walk(search_root):
        # We prioritize the safetensors file you confirmed you have
        if "model.safetensors" in files:
            print(f"✅ [BERT] Found 'model.safetensors' in: {root}")
            return root
        # Fallback check for the old bin format
        if "pytorch_model.bin" in files:
            print(f"✅ [BERT] Found 'pytorch_model.bin' in: {root}")
            return root
            
    print("❌ [BERT] Could not find 'model.safetensors' or 'pytorch_model.bin'.")
    return None

# Locate the path immediately
ACTUAL_MODEL_PATH = find_model_path()

# Global variables
_model = None
_tokenizer = None
_device = "cuda" if torch.cuda.is_available() else "cpu"

def load_model():
    global _model, _tokenizer
    if _model is not None: return

    # Decide source: Local Folder or Cloud Fallback
    if ACTUAL_MODEL_PATH:
        model_source = ACTUAL_MODEL_PATH
        print(f"🔄 [BERT] Loading local model from: {model_source}")
    else:
        print("⚠️ [BERT] Local model missing. Downloading 'bert-base-uncased' from Cloud.")
        model_source = "bert-base-uncased"

    try:
        # 1. Load Tokenizer
        try:
            # Try loading from the same folder as the model
            _tokenizer = BertTokenizer.from_pretrained(model_source)
        except:
            # If vocab.txt is missing locally, download the standard one (Safe fallback)
            print("⚠️ [BERT] Local tokenizer missing. Downloading standard BERT tokenizer.")
            _tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")

        # 2. Load Model (With Safetensors Support)
        _model = BertForSequenceClassification.from_pretrained(
            model_source, 
            use_safetensors=True  # <--- This enables reading your .safetensors file
        )
        
        _model.to(_device)
        _model.eval()
        print("✅ [BERT] Model loaded successfully.")

    except Exception as e:
        print(f"❌ [BERT] Critical Load Error: {e}")
        # Last Resort: Load generic model so the server doesn't crash
        if model_source != "bert-base-uncased":
            print("☁️ [BERT] Attempting fallback to cloud model...")
            try:
                _tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")
                _model = BertForSequenceClassification.from_pretrained("bert-base-uncased")
                _model.to(_device)
                _model.eval()
            except:
                pass

# ==========================================
# 2. VALIDATION LOGIC
# ==========================================
def validate_prediction(label, url_str, query_str):
    """Sanity check to prevent false positives."""
    url_lower = str(url_str).lower()
    query_lower = str(query_str).lower()

    if label == "Remote File Inclusion (RFI)":
        if not any(x in query_lower for x in ['http', 'ftp', '://', '=']):
            return False, "False Positive (No remote protocol)"

    if label == "SQL Injection":
        if not any(x in query_lower for x in ["'", '"', 'select', 'union', '--', '=', 'sleep']):
            return False, "False Positive (No SQL markers)"

    return True, ""

# ==========================================
# 3. PREDICTION LOGIC
# ==========================================

def predict_url_attack(url):
    """
    Pipeline: Split URL -> Tokenize -> Predict -> Validate
    """
    if _model is None:
        load_model()
        if _model is None: return "Benign", 0.0, "AI Unavailable"

    # --- STEP 1: SPLIT URL ---
    try:
        parsed = urllib.parse.urlparse(str(url))
        path = parsed.path
        query = parsed.query
        
        if query:
            # Prompt format: Payload [SEP] Context
            text_a = query 
            text_b = path 
            evidence_hint = "Suspicious parameters."
        else:
            text_a = url
            text_b = None
            evidence_hint = "Suspicious URL path."
    except:
        text_a = url
        text_b = None
        evidence_hint = "Suspicious pattern."

    # --- STEP 2: INFERENCE ---
    try:
        inputs = _tokenizer(
            text=text_a,
            text_pair=text_b,
            return_tensors="pt",
            truncation=True,
            max_length=128,
            padding="max_length"
        ).to(_device)

        with torch.no_grad():
            outputs = _model(**inputs)
            probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
            confidence, predicted_class_id = torch.max(probs, dim=-1)

        predicted_label = _model.config.id2label[predicted_class_id.item()]
        conf_score = confidence.item()

        # --- STEP 3: VALIDATE ---
        if conf_score > 0.85:
            is_valid, reason = validate_prediction(predicted_label, url, query)
            
            if is_valid:
                evidence = f"AI Confidence: {round(conf_score * 100)}%. {evidence_hint}"
                return predicted_label, conf_score, evidence
            else:
                return "Benign", conf_score, reason

        return "Benign", conf_score, "Low AI confidence"

    except Exception as e:
        print(f"Prediction Error: {e}")
        return "Benign", 0.0, "Error"

# ==========================================
# 4. EXPLANATION LOGIC
# ==========================================
def get_explanation(text_input):
    if _tokenizer is None: load_model()
    if _tokenizer is None: return []
    try:
        tokens = _tokenizer.tokenize(text_input)
        return [{"token": t, "weight": 0.1} for t in tokens[:50]]
    except:
        return []