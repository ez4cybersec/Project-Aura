import torch
from transformers import BertTokenizer, BertForMaskedLM
import re

# ==========================================
#  UNIFIED BERT MODEL (Visualizer + Predictive)
# ==========================================
MODEL_NAME = "bert-base-uncased"
_tokenizer = None
_model = None
_device = "cuda" if torch.cuda.is_available() else "cpu"

def _load_model():
    global _tokenizer, _model
    if _model is not None: return _tokenizer, _model
    try:
        print(f"📊 [AI] Loading Unified BERT Model ({_device})...")
        _tokenizer = BertTokenizer.from_pretrained(MODEL_NAME)
        # BertForMaskedLM handles Visualization (Attention) AND Prediction (Masking)
        _model = BertForMaskedLM.from_pretrained(MODEL_NAME, output_attentions=True)
        _model.to(_device)
        _model.eval()
        return _tokenizer, _model
    except Exception as e:
        print(f"❌ [AI] Error: {e}")
        return None, None

def get_explanation(text_input: str):
    """
    PART 1: XAI VISUALIZER (No changes here)
    """
    tokenizer, model = _load_model()
    if model is None: return []
    
    text = str(text_input).strip()
    if not text: return []
    
    inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=128, padding=True).to(_device)
    
    with torch.no_grad():
        outputs = model.bert(**inputs)
        
    last_layer_attention = outputs.attentions[-1][0] 
    avg_attention = last_layer_attention.mean(dim=0)
    cls_attention = avg_attention[0]
    input_ids = inputs["input_ids"][0]
    tokens = tokenizer.convert_ids_to_tokens(input_ids)
    
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

def get_mitigation_advice(attack_type: str):
    """
    PART 2: DYNAMIC PREDICTIVE AI (No Hardcoded Patterns)
    We insert the attack name into a generic template and let BERT 
    predict the best technical term (verb/noun) for that specific context.
    """
    tokenizer, model = _load_model()
    
    # 1. Base Truth
    point_one = "1. Validate and sanitize all input data."
    
    if model is None:
        return f"{point_one}\n2. Block the suspicious source IP."

    # 2. DYNAMIC TEMPLATE (Zero if/else statements)
    # We construct the sentence using the variable directly.
    # BERT reads "SQL Injection" vs "Bruteforce" and predicts a different word for [MASK].
    
    # Clean the name (e.g., "Directory_Traversal" -> "Directory Traversal")
    clean_name = attack_type.replace("_", " ").strip()
    
    # THE UNIVERSAL PROMPT:
    # "To prevent [Attack Name], the system must strictly [MASK] malicious requests."
    template = f"The best technical defense against {clean_name} is to [MASK] the input data."
    # 3. BERT PREDICTION
    inputs = tokenizer(template, return_tensors="pt").to(_device)
    
    # Find the position of [MASK]
    mask_token_index = (inputs.input_ids == tokenizer.mask_token_id)[0].nonzero(as_tuple=True)[0]
    
    with torch.no_grad():
        outputs = model(**inputs)
        
    # Get the predicted word
    logits = outputs.logits[0, mask_token_index, :]
    predicted_token_id = logits.argmax(axis=-1)
    predicted_word = tokenizer.decode(predicted_token_id).strip()

    # 4. CONSTRUCT RESULT
    final_sentence = template.replace("[MASK]", predicted_word)
    
    # Capitalize for neatness
    final_sentence = final_sentence[0].upper() + final_sentence[1:]

    return f"{point_one}\n2. {final_sentence}"