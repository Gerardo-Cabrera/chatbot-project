import re, difflib


def normalize_text(s: str) -> str:
    s = (s or "").lower()
    s = re.sub(r"[^\w\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def trigrams(s: str):
    s = f"  {s}  "
    return [s[i:i+3] for i in range(len(s)-2)]


def trigram_score(a: str, b: str) -> float:
    a = normalize_text(a); b = normalize_text(b)
    if not a or not b: return 0.0
    ta = set(trigrams(a)); tb = set(trigrams(b))
    inter = len(ta & tb)
    if not ta and not tb: return 0.0
    return (2.0 * inter) / (len(ta) + len(tb))


def similarity_score(a: str, b: str) -> float:
    a_n = normalize_text(a); b_n = normalize_text(b)
    seq = difflib.SequenceMatcher(None, a_n, b_n).ratio()
    tri = trigram_score(a_n, b_n)
    return max(seq, tri * 1.05)
