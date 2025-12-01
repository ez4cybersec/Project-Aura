import torch
from transformers import BertTokenizer, BertModel
import numpy as np

# Use the same base model name or path as your main predictor
MODEL_NAME = "bert-base-uncased"

_tokenizer = None
_model = None
_device = "cuda" if torch.cuda.is_available() else "cpu"

def _load_model():
    global _tokenizer, _model
    if _model is not None:
        return _tokenizer, _model

    print(f"📊 [XAI] Loading explainability model ({_device})...")
    try:
        # We load BertModel (not ForSequenceClassification) to get raw attentions easily
        _tokenizer = BertTokenizer.from_pretrained(MODEL_NAME)
        _model = BertModel.from_pretrained(
            MODEL_NAME,
            output_attentions=True  # KEY: This enables the 'explanation' data
        )
        _model.to(_device)
        _model.eval()
        return _tokenizer, _model
    except Exception as e:
        print(f"❌ [XAI] Error loading model: {e}")
        return None, None

def get_explanation(text_input: str, top_k: int = 10):
    """
    Generates a REAL explanation by extracting BERT's attention weights.
    Returns a list of tokens with their importance scores (0.0 - 1.0).
    """
    tokenizer, model = _load_model()
    if model is None:
        return []

    # 1. Prepare Input
    text = str(text_input).strip()
    if not text: return []

    inputs = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        max_length=128,
        padding=True
    ).to(_device)

    # 2. Forward Pass (Get Attentions)
    with torch.no_grad():
        outputs = model(**inputs)
    
    # 3. Extract Attention Weights
    # outputs.attentions is a tuple of tensors (one for each layer)
    # Shape: (batch_size, num_heads, seq_len, seq_len)
    # We use the LAST layer as it represents the final "decision" layer.
    last_layer_attention = outputs.attentions[-1][0]  # Remove batch dim -> (num_heads, seq, seq)
    
    # Average attention across all heads to get a general "focus"
    avg_attention = last_layer_attention.mean(dim=0)  # -> (seq, seq)

    # The [CLS] token (index 0) is the classification token. 
    # We look at how much attention [CLS] paid to every other token.
    cls_attention = avg_attention[0]  # -> (seq_len, )

    # 4. Map Scores to Tokens
    input_ids = inputs["input_ids"][0]
    tokens = tokenizer.convert_ids_to_tokens(input_ids)
    
    # Filter special tokens and pair with scores
    explanation = []
    max_score = 0.0

    for i, token in enumerate(tokens):
        # Skip special BERT tokens that users don't need to see
        if token in ["[CLS]", "[SEP]", "[PAD]"]:
            continue
            
        score = cls_attention[i].item()
        if score > max_score: max_score = score
        
        explanation.append({
            "token": token,
            "weight": score
        })

    # 5. Normalize Scores (0 to 1 scale for UI)
    # This makes the "most important" word always have a full bar/color
    if max_score > 0:
        for item in explanation:
            item["weight"] = round(item["weight"] / max_score, 4)

    # 6. Sort by importance (Optional: helpful for debugging)
    # explanation.sort(key=lambda x: x["weight"], reverse=True)

    # Return just the top K most relevant, or all if you prefer
    # (UI usually handles the full list better for highlighting)
    return explanation