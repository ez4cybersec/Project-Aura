import torch
import os
import re
from transformers import AutoTokenizer, AutoModelForSequenceClassification, AutoModelForCausalLM
from captum.attr import LayerIntegratedGradients
from huggingface_hub import login

# ==========================================
#   0. SECURITY & AUTH
# ==========================================
HF_TOKEN = None

try:
    from .secrets import HF_TOKEN
except ImportError:
    pass

if not HF_TOKEN:
    HF_TOKEN = os.getenv("HF_TOKEN")

if HF_TOKEN:
    login(token=HF_TOKEN)

# ==========================================
#   DEVICE SETUP
# ==========================================
_device = "cuda" if torch.cuda.is_available() else "cpu"
print(f"⚙️ Running on device: {_device.upper()}")

# ================================================================
#   1. SECBERT CLASSIFIER (Global Load)
# ================================================================
CLASSIFIER_MODEL_NAME = "jackaduma/SecBERT"
_classifier_tokenizer = None
_classifier_model = None

CLASS_INDEX_MAP = {
    "SQL Injection": 0, "SQL_INJECTION": 0,
    "XSS": 1, "Cross-Site Scripting": 1,
    "Directory Traversal": 2, "DIRECTORY_TRAVERSAL": 2,
    "Command Injection": 3, "COMMAND_INJECTION": 3,
    "SSRF": 4, 
    "LFI/RFI": 5, 
    "XXE": 6,
    "Other": 0 
}

# --- STOP WORDS: Tokens that should NEVER be highlighted ---
# These are structural elements that confuse the user if highlighted.
IGNORE_TOKENS = {
    "http", "https", "ftp", "www", "com", "org", "net",
    "127", "0", "1", "localhost", "ip",
    ":", "/", ".", "?", "&", "=", "-", "_", "%",
    "protocol", "host", "port", "user", "agent",
    "[CLS]", "[SEP]", "[PAD]"
}

def _load_classifier():
    global _classifier_tokenizer, _classifier_model
    if _classifier_model is not None:
        return _classifier_tokenizer, _classifier_model

    print(f"📊 Loading SecBERT...")
    try:
        _classifier_tokenizer = AutoTokenizer.from_pretrained(CLASSIFIER_MODEL_NAME)
        _classifier_model = AutoModelForSequenceClassification.from_pretrained(
            CLASSIFIER_MODEL_NAME, num_labels=7
        ).to(_device)
        _classifier_model.eval()
        return _classifier_tokenizer, _classifier_model
    except Exception as e:
        print(f"❌ SecBERT Load Error: {e}")
        return None, None

# ================================================================
#   2. CAPTUM EXPLANATION (Visual Analysis)
# ================================================================
def get_explanation(text_input: str, attack_type_str: str):
    tokenizer, model = _load_classifier()
    if not model: return []

    text = str(text_input).strip()
    if not text: return []

    target_class = CLASS_INDEX_MAP.get(attack_type_str, 0)

    # 1. Tokenize
    encoded = tokenizer(
        text, return_tensors="pt", truncation=True, max_length=128, padding=True
    ).to(_device)
    
    input_ids = encoded["input_ids"]
    attention_mask = encoded["attention_mask"]

    # 2. Define Forward Function
    def forward_func(inputs, mask):
        out = model(input_ids=inputs, attention_mask=mask)
        return out.logits[:, target_class]

    # 3. Compute Gradients
    target_layer = model.bert.embeddings
    lig = LayerIntegratedGradients(forward_func, target_layer)

    try:
        attributions, delta = lig.attribute(
            inputs=input_ids,
            additional_forward_args=(attention_mask,),
            n_steps=50,
            return_convergence_delta=True
        )
    except Exception:
        return []

    # 4. Process Attributions
    token_importance = attributions.sum(dim=-1).squeeze(0)
    
    # 5. Clean & Filter Logic
    tokens = tokenizer.convert_ids_to_tokens(input_ids[0])
    explanation = []
    
    # Track the maximum score for normalization
    max_score = 0.0
    
    for i, (tok, score_tensor) in enumerate(zip(tokens, token_importance)):
        raw_score = float(score_tensor.cpu().item())
        
        # A. Absolute value (Negative gradients are also important)
        abs_score = abs(raw_score)

        # B. FILTER: Ignore structural tokens
        # If the token is in our ignore list, or is a single punctuation mark, kill the score.
        clean_tok = tok.replace("##", "").lower()
        if clean_tok in IGNORE_TOKENS or (len(clean_tok) == 1 and not clean_tok.isalnum()):
            abs_score = 0.0
        
        # C. Track Max
        if abs_score > max_score:
            max_score = abs_score
            
        explanation.append({
            "token": tok,
            "weight": abs_score, # Store raw absolute score first
            "original_index": i
        })

    # 6. Normalize relative to the MAX score (Contrast Enhancement)
    # This ensures the most important token is always 1.0 (Brightest Red)
    final_explanation = []
    if max_score > 0:
        for item in explanation:
            # Only keep items with significant weight (> 10% of max) to reduce noise
            normalized_weight = item["weight"] / max_score
            
            # Threshold: If it's less than 15% as important as the top token, hide it.
            if normalized_weight < 0.15: 
                normalized_weight = 0.0
            
            if item["token"] not in ["[CLS]", "[SEP]", "[PAD]"]:
                final_explanation.append({
                    "token": item["token"],
                    "weight": round(normalized_weight, 4)
                })
    
    return final_explanation

# ================================================================
#   3. GEMMA MITIGATION (Generative AI)
# ================================================================
GEMMA_MODEL_NAME = "google/gemma-3-270m-it" 
_ai_model = None
_ai_tokenizer = None

def _load_gemma():
    global _ai_model, _ai_tokenizer
    if _ai_model is not None: return _ai_tokenizer, _ai_model

    try:
        _ai_tokenizer = AutoTokenizer.from_pretrained(GEMMA_MODEL_NAME)
        dtype = torch.bfloat16 if (_device == "cuda" and torch.cuda.is_bf16_supported()) else torch.float32
        
        _ai_model = AutoModelForCausalLM.from_pretrained(
            GEMMA_MODEL_NAME,
            device_map="auto" if _device == "cuda" else None,
            torch_dtype=dtype,
            low_cpu_mem_usage=True
        )
        if _device == "cpu": _ai_model.to(_device)
        _ai_model.eval()
        return _ai_tokenizer, _ai_model
    except Exception as e:
        print(f"❌ Gemma Load Error: {e}")
        return None, None

def get_mitigation_advice(text_input: str, attack_type: str, explanation: list):
    tokenizer, model = _load_gemma()
    if model is None: return "AI Mitigation service unavailable."

    # Sort to find most suspicious tokens for context
    sorted_exp = sorted(explanation, key=lambda x: abs(x["weight"]), reverse=True)
    # Filter out tokens with 0 weight from context
    top_tokens = [f"'{e['token']}'" for e in sorted_exp if e['weight'] > 0][:3]
    xai_context = ", ".join(top_tokens)

    prompt = f"""<start_of_turn>user
You are a Security Engineer. 
Attack: {attack_type}
Payload: "{text_input}"
Suspicious Tokens: {xai_context}

Provide exactly 2 technical mitigation steps.
Format:
1. [Step 1]
2. [Step 2]<end_of_turn>
<start_of_turn>model
"""

    inputs = tokenizer(prompt, return_tensors="pt").to(_device)

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=100,
            do_sample=False,
            repetition_penalty=1.2
        )

    full_output = tokenizer.decode(outputs[0], skip_special_tokens=True)
    
    if "model\n" in full_output:
        response_text = full_output.split("model\n")[-1].strip()
    else:
        response_text = full_output.strip()

    clean_text = response_text.replace("**", "").replace("* ", "")
    return clean_text.strip()