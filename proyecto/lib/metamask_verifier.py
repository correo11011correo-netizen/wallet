import os, hashlib
from typing import Dict, Any, List

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
WORDLIST_PATH = os.path.join(BASE_DIR, "lib", "wordlist_english_clean.txt")

def load_wordlist(path=WORDLIST_PATH) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        words = [w.strip() for w in f if w.strip()]
    if len(words) != 2048:
        raise ValueError("Wordlist inválida: debe tener 2048 palabras.")
    if len(set(words)) != 2048:
        raise ValueError("Wordlist contiene duplicados.")
    return words

def words_to_indices(words: List[str], wordlist: List[str]) -> List[int]:
    idx_map = {w: i for i, w in enumerate(wordlist)}
    indices = []
    for w in words:
        if w not in idx_map:
            raise ValueError(f"Palabra inválida: {w}")
        indices.append(idx_map[w])
    return indices

def indices_to_bitstring(indices: List[int]) -> str:
    return "".join(format(i, "011b") for i in indices)

def bits_to_bytes(bitstr: str) -> bytes:
    if len(bitstr) % 8 != 0:
        raise ValueError("Entropía no múltiplo de 8 bits.")
    return int(bitstr, 2).to_bytes(len(bitstr)//8, "big")

def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def checksum_bits(entropy_bytes: bytes, length: int) -> str:
    h = sha256_bytes(entropy_bytes)
    h_bits = "".join(format(b, "08b") for b in h)
    return h_bits[:length]

def derive_seed(mnemonic: str, passphrase: str="") -> bytes:
    salt = ("mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), salt, 2048, dklen=64)

def verify_metamask_phrase(phrase: str, passphrase: str="") -> Dict[str, Any]:
    result = {"valid": False, "errors": [], "sha256": None, "sha512": None}
    words = phrase.strip().lower().split()

    # 1) Longitud fija
    if len(words) != 12:
        result["errors"].append("MetaMask solo acepta frases de 12 palabras.")
        return result

    # 2) Wordlist
    wl = load_wordlist()
    try:
        indices = words_to_indices(words, wl)
    except Exception as e:
        result["errors"].append(str(e))
        return result

    # 3) Flujo de bits
    bitstr = indices_to_bitstring(indices)
    entropy_bits_len = 128
    checksum_bits_len = 4
    ent_bits = bitstr[:entropy_bits_len]
    chk_bits = bitstr[entropy_bits_len:entropy_bits_len+checksum_bits_len]

    # 4) Entropía múltiplo de 8
    try:
        entropy_bytes = bits_to_bytes(ent_bits)
    except Exception as e:
        result["errors"].append(str(e))
        return result

    # 5) Checksum
    expected_chk = checksum_bits(entropy_bytes, checksum_bits_len)
    if chk_bits != expected_chk:
        result["errors"].append("Checksum inválido.")
        return result

    # 6) Derivación de semilla
    seed = derive_seed(" ".join(words), passphrase)
    result["sha256"] = hashlib.sha256(seed).hexdigest()
    result["sha512"] = hashlib.sha512(seed).hexdigest()
    result["valid"] = True
    return result
