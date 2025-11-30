import torch
from transformers import AutoTokenizer, AutoModel

MODEL_NAME = "bert-base-uncased"

_tokenizer = None
_model = None


def _load_model():
    global _tokenizer, _model
    if _model is not None:
        return _tokenizer, _model

    _tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    _model = AutoModel.from_pretrained(
        MODEL_NAME,
        output_attentions=True  # we need attentions for explainability
    )
    _model.eval()
    return _tokenizer, _model


def explain_with_bert(text: str, top_k: int = 8):
    """
    Use BERT self-attention to highlight the most important tokens
    in the given text. This does NOT change your attack_type.
    It only explains which words look salient to BERT.
    """
    tokenizer, model = _load_model()

    text = text or ""
    inputs = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        max_length=128
    )

    with torch.no_grad():
        outputs = model(**inputs)

    # outputs.attentions is a list: [layer] -> (batch, heads, seq, seq)
    attentions = outputs.attentions

    # Take last layer, average over heads, then attention from [CLS] to others
    last_layer_attn = attentions[-1][0]          # (heads, seq, seq)
    mean_heads = last_layer_attn.mean(dim=0)     # (seq, seq)
    cls_to_tokens = mean_heads[0]               # attention from CLS (position 0) to all tokens  (seq,)

    tokens = tokenizer.convert_ids_to_tokens(inputs["input_ids"][0])

    features = []
    for tok, score in zip(tokens, cls_to_tokens.tolist()):
        # Skip boring special tokens
        if tok in ["[CLS]", "[SEP]", "[PAD]"]:
            continue
        features.append({"token": tok, "weight": float(score)})

    # Sort by importance and keep top_k
    features.sort(key=lambda x: x["weight"], reverse=True)
    features = features[:top_k]

    # Normalize weights between 0 and 1 for nicer UI (optional)
    if features:
        max_w = max(f["weight"] for f in features)
        if max_w > 0:
            for f in features:
                f["weight"] = f["weight"] / max_w

    return {"features": features}
