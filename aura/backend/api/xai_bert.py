import torch
from transformers import BertTokenizer, BertForMaskedLM
from transformers import AutoTokenizer, AutoModelForCausalLM

# ==========================================
#  BERT MODEL (For Visualizer Only)
# ==========================================
BERT_MODEL_NAME = "bert-base-uncased"
_bert_tokenizer = None
_bert_model = None
_device = "cuda" if torch.cuda.is_available() else "cpu"

def _load_bert():
    global _bert_tokenizer, _bert_model
    if _bert_model is not None: return _bert_tokenizer, _bert_model
    try:
        print(f"📊 [XAI] Loading BERT ({_device})...")
        _bert_tokenizer = BertTokenizer.from_pretrained(BERT_MODEL_NAME)
        _bert_model = BertForMaskedLM.from_pretrained(BERT_MODEL_NAME, output_attentions=True)
        _bert_model.to(_device)
        _bert_model.eval()
        print("✅ [XAI] BERT loaded!")
        return _bert_tokenizer, _bert_model
    except Exception as e:
        print(f"❌ [XAI] BERT Error: {e}")
        return None, None

def get_explanation(text_input: str):
    """
    Analyzes text and returns tokens with attention weights for the UI.
    """
    tokenizer, model = _load_bert()
    if model is None: return []
    
    text = str(text_input).strip()
    if not text: return []
    
    inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=128, padding=True).to(_device)
    
    with torch.no_grad():
        outputs = model.bert(**inputs)
        
    last_layer_attention = outputs.attentions[-1][0] 
    avg_attention = last_layer_attention.mean(dim=0)
    cls_attention = avg_attention[0]
    
    tokens = tokenizer.convert_ids_to_tokens(inputs["input_ids"][0])
    explanation = []
    max_score = 0.0
    
    for i, token in enumerate(tokens):
        if token in ["[CLS]", "[SEP]", "[PAD]"]: continue
        score = cls_attention[i].item()
        if score > max_score: max_score = score
        explanation.append({"token": token, "weight": score})
    
    if max_score > 0:
        for item in explanation:
            item["weight"] = round(item["weight"] / max_score, 4)
            
    return explanation

# ==========================================
#  GEN-AI MODEL (For General Advice)
# ==========================================
LLAMA_MODEL_NAME = "TinyLlama/TinyLlama-1.1B-Chat-v1.0" 
_llama_tokenizer = None
_llama_model = None

def _load_llama():
    global _llama_tokenizer, _llama_model
    if _llama_model is not None: return _llama_tokenizer, _llama_model
    try:
        print(f"🤖 [AI] Loading TinyLlama on {_device}...")
        _llama_tokenizer = AutoTokenizer.from_pretrained(LLAMA_MODEL_NAME)
        if _llama_tokenizer.pad_token is None:
            _llama_tokenizer.pad_token = _llama_tokenizer.eos_token
        
        # CPU Optimization
        use_dtype = torch.float16 if _device == "cuda" else torch.float32
        _llama_model = AutoModelForCausalLM.from_pretrained(
            LLAMA_MODEL_NAME, torch_dtype=use_dtype, low_cpu_mem_usage=True
        )
        _llama_model.to(_device)
        _llama_model.eval()
        print(f"✅ [AI] TinyLlama loaded!")
        return _llama_tokenizer, _llama_model
    except Exception as e:
        print(f"❌ [AI] Model Load Error: {e}")
        return None, None

def get_mitigation_advice(attack_text, attack_type, bert_explanation):
    """
    V11: Few-Shot Pattern Mode.
    We give the AI an example to force it to copy the format and logic.
    This fixes the "HTTPS" hallucination and ensures 2 accurate points.
    """
    tokenizer, model = _load_llama()
    if model is None: return "AI unavailable."
    
    clean_type = attack_type.replace("_", " ").strip()

    # --- THE MAGIC FIX: FEW-SHOT PROMPTING ---
    # We show it a "Q&A" pattern. It just has to fill in the blank.
    prompt = (
        f"<|user|>\n"
        f"Task: List exactly 2 technical fixes for the security vulnerability.\n\n"
        f"Example Input: SQL Injection\n"
        f"Example Output:\n"
        f"1. Use prepared statements (parameterized queries) in database calls.\n"
        f"2. Sanitize and validate all user inputs before processing.\n\n"
        f"Real Input: {clean_type}\n"
        f"Real Output:\n"
        f"1." # We start the numbering to force the format
    )
    
    try:
        inputs = tokenizer(prompt, return_tensors="pt").to(_device)
        
        print(f"⏳ [AI] Generating pattern-matched advice for {clean_type}...") 
        
        with torch.no_grad():
            outputs = model.generate(
                inputs.input_ids,
                attention_mask=inputs.attention_mask,
                max_new_tokens=60,    # Very short limit (Prevents rambling)
                do_sample=False,      # Deterministic
                repetition_penalty=1.2,
                pad_token_id=tokenizer.eos_token_id
            )
        
        raw_output = tokenizer.decode(outputs[0], skip_special_tokens=True)
        
        # Clean Output: extract only the "Real Output" part
        if "Real Output:" in raw_output:
            final_output = raw_output.split("Real Output:")[-1].strip()
        else:
            final_output = raw_output.split("<|assistant|>")[-1].strip()

        # Formatting Fixes
        if not final_output.startswith("1."):
            final_output = "1. " + final_output
            
        # Ensure point 2 exists and is on a new line
        final_output = final_output.replace("2.", "\n2.")

        # --- SAFETY SCISSORS ---
        # Cut off any half-finished 3rd point or trailing text
        if "\n3." in final_output:
            final_output = final_output.split("\n3.")[0]
            
        # Ensure it ends cleanly
        valid_endings = ['.', '!', '?', '\n']
        if final_output and final_output[-1] not in valid_endings:
            last_period = final_output.rfind('.')
            if last_period != -1:
                final_output = final_output[:last_period+1]

        print("✅ [AI] Generation Complete")
        return final_output
            
    except Exception as e:
        print(f"❌ [AI] Error: {e}")
        # Fallback if AI crashes
        return "1. Validate all user input against a whitelist. 2. Update server security configurations."