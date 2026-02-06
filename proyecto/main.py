#!/usr/bin/env python3
# flake8: noqa
#Merged library file
# Contains code from the following files:
# - bip32.py
# - bip39seed.py
# - bip44.py
# - bip44coin.py
# - biputils.py
# - keccak.py
# - metamask_verifier.py
# - mnemonic.py
# - secp256k1.py
# - verifier.py

# From: biputils.py
import hashlib
import hmac
from typing import Tuple, List, Dict, Any
import os
import json
import requests
import sys

# PBKDF2-HMAC-SHA512 (BIP39)
def pbkdf2_sha512(password: bytes, salt: bytes, iterations: int = 2048, dklen: int = 64) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", password, salt, iterations, dklen=dklen)

# HMAC-SHA512 (BIP32 CKD)
def hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def ripemd160(data: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(data)
    return h.digest()

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")

def int_to_bytes(i: int, length: int) -> bytes:
    return i.to_bytes(length, "big")

# Base58 (para formatos Bitcoin; no usado en Ethereum)
_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58_encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    res = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        res.append(_ALPHABET[r])
    # manejo de ceros a la izquierda
    pad = 0
    for c in b:
        if c == 0:
            pad += 1
        else:
            break
    return (b"1" * pad + res[::-1]).decode("ascii")

# From: secp256k1.py
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A  = 0
B  = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

G = (Gx, Gy)

def inverse_mod(k: int, p: int = P) -> int:
    if k % p == 0:
        raise ZeroDivisionError("inverse_mod of zero")
    return pow(k, p - 2, p)

def is_on_curve(Pt):
    if Pt is None: return True
    x, y = Pt
    return (y * y - (x * x * x + A * x + B)) % P == 0

def point_add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2 and y1 != y2:
        return None
    if P1 == P2:
        # tangent slope
        m = (3 * x1 * x1 + A) * inverse_mod(2 * y1, P) % P
    else:
        m = (y2 - y1) * inverse_mod((x2 - x1) % P, P) % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)

def scalar_mult(k: int, point=G):
    if k % N == 0 or point is None:
        return None
    k = k % N
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    if not is_on_curve(result):
        raise ValueError("Resultado fuera de la curva")
    return result

def privkey_to_pubkey_uncompressed(privkey_bytes: bytes) -> bytes:
    k = int.from_bytes(privkey_bytes, "big")
    if not (1 <= k < N):
        raise ValueError("Clave privada fuera de rango")
    x, y = scalar_mult(k, G)
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")

def privkey_to_pubkey_compressed(privkey_bytes: bytes) -> bytes:
    k = int.from_bytes(privkey_bytes, "big")
    if not (1 <= k < N):
        raise ValueError("Clave privada fuera de rango")
    x, y = scalar_mult(k, G)
    prefix = b"\x02" if (y % 2 == 0) else b"\x03"
    return prefix + x.to_bytes(32, "big")


# From: bip32.py
def ser256(x: int) -> bytes:
    return x.to_bytes(32, "big")

def ser32(i: int) -> bytes:
    return i.to_bytes(4, "big")

def serP_compressed(point: Tuple[int,int]) -> bytes:
    x, y = point
    prefix = 0x02 if (y % 2 == 0) else 0x03
    return bytes([prefix]) + x.to_bytes(32, "big")

def hash160(b: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()

class BIP32Node:
    def __init__(self, privkey: int, chaincode: bytes):
        self.k = privkey            # entero privado
        self.chaincode = chaincode  # 32 bytes
        self.privkey = ser256(privkey)  # cache en bytes

    @staticmethod
    def master_from_seed(seed: bytes) -> 'BIP32Node':
        I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        IL, IR = I[:32], I[32:]
        k = int.from_bytes(IL, "big")
        if k == 0 or k >= N:
            raise ValueError("Master key fuera de rango")
        return BIP32Node(k, IR)

    def ckd_priv(self, index: int, hardened: bool) -> 'BIP32Node':
        if hardened:
            data = b"\x00" + ser256(self.k) + ser32(index | 0x80000000)
        else:
            # usar pubkey comprimido del padre
            Px, Py = scalar_mult(self.k, G)
            data = serP_compressed((Px, Py)) + ser32(index)
        I = hmac.new(self.chaincode, data, hashlib.sha512).digest()
        IL, IR = I[:32], I[32:]
        child_k = (int.from_bytes(IL, "big") + self.k) % N
        if child_k == 0:
            raise ValueError("Child key inválida (zero)")
        return BIP32Node(child_k, IR)

# From: bip39seed.py
class Bip39SeedGenerator:
    def __init__(self, mnemonic: str):
        self.mnemonic = mnemonic

    def Generate(self, passphrase: str = "") -> bytes:
        # salt = "mnemonic" + passphrase
        salt = ("mnemonic" + passphrase).encode("utf-8")
        return pbkdf2_sha512(self.mnemonic.encode("utf-8"), salt, iterations=2048, dklen=64)

# From: keccak.py
RC = [
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008
]
RHO = [
    [ 0, 36,  3, 41, 18],
    [ 1, 44, 10, 45,  2],
    [62,  6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39,  8, 14],
]
def _rotl64(x, n):
    n &= 63
    return ((x << n) & ((1 << 64) - 1)) | (x >> (64 - n))
def _index(x, y):
    return x + 5 * y
def keccak_f1600(state):
    for rnd in range(24):
        C = [state[_index(x,0)] ^ state[_index(x,1)] ^ state[_index(x,2)] ^ state[_index(x,3)] ^ state[_index(x,4)] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rotl64(C[(x + 1) % 5], 1) for x in range(5)]
        for y in range(5):
            for x in range(5):
                state[_index(x,y)] ^= D[x]
        B = [0] * 25
        for y in range(5):
            for x in range(5):
                X = y
                Y = (2*x + 3*y) % 5
                B[_index(X,Y)] = _rotl64(state[_index(x,y)], RHO[x][y])
        for y in range(5):
            t0 = B[_index(0,y)]
            t1 = B[_index(1,y)]
            t2 = B[_index(2,y)]
            t3 = B[_index(3,y)]
            t4 = B[_index(4,y)]
            state[_index(0,y)] = t0 ^ ((~t1) & t2)
            state[_index(1,y)] = t1 ^ ((~t2) & t3)
            state[_index(2,y)] = t2 ^ ((~t3) & t4)
            state[_index(3,y)] = t3 ^ ((~t4) & t0)
            state[_index(4,y)] = t4 ^ ((~t0) & t1)
        state[0] ^= RC[rnd]
def keccak256(data: bytes) -> bytes:
    rate = 1088 // 8
    outlen = 256 // 8
    state = [0] * 25
    i = 0
    while i + rate <= len(data):
        block = data[i:i+rate]
        for j in range(0, rate, 8):
            lane = int.from_bytes(block[j:j+8], "little")
            state[j // 8] ^= lane
        keccak_f1600(state)
        i += rate
    rem = data[i:]
    pad = bytearray(rem)
    pad += b"\x01"
    pad += b"\x00" * (rate - len(pad) - 1)
    pad += b"\x80"
    for j in range(0, rate, 8):
        lane = int.from_bytes(pad[j:j+8], "little")
        state[j // 8] ^= lane
    keccak_f1600(state)
    out = bytearray()
    while len(out) < outlen:
        for j in range(0, rate, 8):
            out += state[j // 8].to_bytes(8, "little")
            if len(out) >= outlen:
                break
        if len(out) >= outlen:
            break
        keccak_f1600(state)
    return bytes(out[:outlen])

# From: bip44.py
def _extract_priv_bytes(node: BIP32Node) -> bytes:
    if hasattr(node, "k") and isinstance(node.k, int):
        return node.k.to_bytes(32, "big")
    if hasattr(node, "privkey") and isinstance(node.privkey, int):
        return node.privkey.to_bytes(32, "big")
    if hasattr(node, "privkey") and isinstance(node.privkey, (bytes, bytearray)):
        b = bytes(node.privkey)
        return b if len(b) == 32 else int.from_bytes(b, "big").to_bytes(32, "big")
    if hasattr(node, "privkey_bytes") and isinstance(node.privkey_bytes, (bytes, bytearray)):
        b = bytes(node.privkey_bytes)
        return b if len(b) == 32 else int.from_bytes(b, "big").to_bytes(32, "big")
    raise ValueError("No se pudo extraer la clave privada del nodo BIP32 en 32 bytes")

class _KeyRaw:
    def __init__(self, b: bytes):
        self._b = b
    def ToHex(self) -> str:
        return self._b.hex()

class _PrivateKey:
    def __init__(self, privkey_bytes: bytes):
        self._priv = privkey_bytes
    def Raw(self) -> _KeyRaw:
        return _KeyRaw(self._priv)

class _PublicKey:
    def __init__(self, privkey_bytes: bytes):
        self._priv = privkey_bytes
    def ToAddress(self) -> str:
        pub = privkey_to_pubkey_uncompressed(self._priv)
        addr = keccak256(pub[1:])[-20:]
        return "0x" + addr.hex()

class _Node:
    def __init__(self, node: BIP32Node, coin_def: dict):
        self._node = node
        self._coin = coin_def

    def PrivateKey(self) -> _PrivateKey:
        return _PrivateKey(_extract_priv_bytes(self._node))

    def PublicKey(self) -> _PublicKey:
        return _PublicKey(_extract_priv_bytes(self._node))

    def Purpose(self):
        child = self._node.ckd_priv(self._coin["purpose"], hardened=True)
        return _Node(child, self._coin)

    def Coin(self):
        child = self._node.ckd_priv(self._coin["coin_type"], hardened=True)
        return _Node(child, self._coin)

    def Account(self, index: int):
        child = self._node.ckd_priv(index, hardened=True)
        return _Node(child, self._coin)

    def Change(self, change: int):
        child = self._node.ckd_priv(change, hardened=False)
        return _Node(child, self._coin)

    def AddressIndex(self, index: int):
        child = self._node.ckd_priv(index, hardened=False)
        return _Node(child, self._coin)

    def DerivePath(self, account: int, change: int, index: int):
        n = self._node.ckd_priv(self._coin["purpose"], hardened=True)
        n = n.ckd_priv(self._coin["coin_type"], hardened=True)
        n = n.ckd_priv(account, hardened=True)
        n = n.ckd_priv(change, hardened=False)
        n = n.ckd_priv(index, hardened=False)
        return _Node(n, self._coin)

class Bip44:
    @staticmethod
    def FromSeed(seed_bytes: bytes, coin_def: dict) -> _Node:
        master = BIP32Node.master_from_seed(seed_bytes)
        return _Node(master, coin_def)

# From: bip44coin.py
class Bip44Coins:
    ETHEREUM     = {"purpose": 44, "coin_type": 60}
    BITCOIN      = {"purpose": 44, "coin_type": 0}
    LITECOIN     = {"purpose": 44, "coin_type": 2}
    DOGECOIN     = {"purpose": 44, "coin_type": 3}
    RIPPLE       = {"purpose": 44, "coin_type": 144}
    BITCOIN_CASH = {"purpose": 44, "coin_type": 145}
    DASH         = {"purpose": 44, "coin_type": 5}
    ZCASH        = {"purpose": 44, "coin_type": 133}
    TRON         = {"purpose": 44, "coin_type": 195}
    POLYGON      = {"purpose": 44, "coin_type": 966}
    BSC          = {"purpose": 44, "coin_type": 9006}

# From: mnemonic.py
class Mnemonic:
    def __init__(self, language: str = "english", wordlist_path: str = None):
        if language != "english":
            raise ValueError("Solo 'english' soportado.")
        if not wordlist_path:
            raise ValueError("Se requiere path a wordlist inglesa BIP39.")
        self.wordlist = self._load_wordlist(wordlist_path)
        if len(self.wordlist) != 2048:
            raise ValueError(f"Wordlist debe tener 2048 palabras BIP39. Encontradas: {len(self.wordlist)}")

    def _load_wordlist(self, path: str) -> List[str]:
        with open(path, "r", encoding="utf-8") as f:
            return [w.strip() for w in f.readlines() if w.strip()]

    def generate(self, strength: int = 128) -> str:
        if strength not in (128, 160, 192, 224, 256):
            raise ValueError("Strength inválido. Use 128,160,192,224,256.")
        ent = os.urandom(strength // 8)
        entropy_bits = bin(int.from_bytes(ent, "big"))[2:].zfill(strength)
        hash_bits = bin(int.from_bytes(sha256(ent), "big"))[2:].zfill(256)
        cs_len = strength // 32
        checksum_bits = hash_bits[:cs_len]
        bits = entropy_bits + checksum_bits
        indices = [int(bits[i*11:(i+1)*11], 2) for i in range(len(bits)//11)]
        words = [self.wordlist[idx] for idx in indices]
        return " ".join(words)

    def validate(self, words: str) -> bool:
        parts = words.strip().split()
        if len(parts) not in (12, 15, 18, 21, 24):
            return False
        try:
            indices = [self.wordlist.index(w) for w in parts]
        except ValueError:
            return False
        bitstr = "".join(bin(i)[2:].zfill(11) for i in indices)
        total_len = len(bitstr)
        cs_len = total_len // 33
        ent_len = total_len - cs_len
        entropy_bits = bitstr[:ent_len]
        checksum_bits = bitstr[ent_len:]
        ent_bytes = int(entropy_bits, 2).to_bytes(ent_len // 8, "big")
        hash_bits = bin(int.from_bytes(sha256(ent_bytes), "big"))[2:].zfill(256)
        return checksum_bits == hash_bits[:cs_len]

# From: metamask_verifier.py
BASE_DIR = os.path.dirname(__file__)
WORDLIST_PATH = os.path.join(BASE_DIR, "wordlist_english_clean.txt")

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

    if len(words) != 12:
        result["errors"].append("MetaMask solo acepta frases de 12 palabras.")
        return result

    wl = load_wordlist()
    try:
        indices = words_to_indices(words, wl)
    except Exception as e:
        result["errors"].append(str(e))
        return result

    bitstr = indices_to_bitstring(indices)
    entropy_bits_len = 128
    checksum_bits_len = 4
    ent_bits = bitstr[:entropy_bits_len]
    chk_bits = bitstr[entropy_bits_len:entropy_bits_len+checksum_bits_len]

    try:
        entropy_bytes = bits_to_bytes(ent_bits)
    except Exception as e:
        result["errors"].append(str(e))
        return result

    expected_chk = checksum_bits(entropy_bytes, checksum_bits_len)
    if chk_bits != expected_chk:
        result["errors"].append("Checksum inválido.")
        return result

    seed = derive_seed(" ".join(words), passphrase)
    result["sha256"] = hashlib.sha256(seed).hexdigest()
    result["sha512"] = hashlib.sha512(seed).hexdigest()
    result["valid"] = True
    return result

# From verifier.py
VALID_WORD_COUNTS = {12, 15, 18, 21, 24}
ENTROPY_BITS_BY_COUNT = {
    12: 128,
    15: 160,
    18: 192,
    21: 224,
    24: 256,
}
def split_entropy_and_checksum(bitstr: str, word_count: int) -> Tuple[str, str]:
    if word_count not in VALID_WORD_COUNTS:
        raise ValueError(f"Cantidad de palabras inválida: {word_count}")
    entropy_bits = ENTROPY_BITS_BY_COUNT[word_count]
    checksum_bits = entropy_bits // 32
    total_bits_expected = entropy_bits + checksum_bits
    if len(bitstr) != word_count * 11:
        raise ValueError("Longitud total de bits no coincide con N*11.")
    if total_bits_expected != len(bitstr):
        raise ValueError("La combinación entropía+checksum no coincide con N*11 bits.")
    ent_bits = bitstr[:entropy_bits]
    chk_bits = bitstr[entropy_bits:entropy_bits + checksum_bits]
    return ent_bits, chk_bits

def checksum_bits_from_entropy(entropy_bytes: bytes, checksum_len_bits: int) -> str:
    h = sha256_bytes(entropy_bytes)
    h_bits = "".join(format(b, "08b") for b in h)
    return h_bits[:checksum_len_bits]

def derive_seed_pbkdf2(mnemonic: str, passphrase: str = "") -> bytes:
    salt = ("mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), salt, 2048, dklen=64)

def try_lib_seed(mnemonic: str, passphrase: str = "") -> bytes:
    return derive_seed_pbkdf2(mnemonic, passphrase=passphrase)

def validate_mnemonic_full(phrase: str, wordlist_path: str = WORDLIST_PATH, passphrase: str = "") -> Dict[str, Any]:
    cleaned = " ".join(phrase.strip().lower().split())
    words = cleaned.split()
    result: Dict[str, Any] = {
        "normalized": cleaned,
        "word_count": len(words),
        "length_valid": False,
        "wordlist_ok": False,
        "entropy_bits": None,
        "checksum_bits": None,
        "bitstring_len": None,
        "entropy_bytes_len": None,
        "checksum_valid": False,
        "seed_sha256": None,
        "seed_sha512": None,
        "errors": []
    }
    n = len(words)
    if n in VALID_WORD_COUNTS:
        result["length_valid"] = True
    else:
        result["errors"].append(f"Cantidad de palabras inválida: {n}.")
        return result
    try:
        wl = load_wordlist(wordlist_path)
        indices = words_to_indices(words, wl)
        result["wordlist_ok"] = True
    except Exception as e:
        result["errors"].append(str(e))
        return result
    bitstr = indices_to_bitstring(indices)
    result["bitstring_len"] = len(bitstr)
    try:
        entropy_bits_len = ENTROPY_BITS_BY_COUNT[n]
        checksum_bits_len = entropy_bits_len // 32
        result["entropy_bits"] = entropy_bits_len
        result["checksum_bits"] = checksum_bits_len
        ent_bits, chk_bits = split_entropy_and_checksum(bitstr, n)
    except Exception as e:
        result["errors"].append(str(e))
        return result
    try:
        entropy_bytes = bits_to_bytes(ent_bits)
        result["entropy_bytes_len"] = len(entropy_bytes)
    except Exception as e:
        result["errors"].append(str(e))
        return result
    expected_chk = checksum_bits_from_entropy(entropy_bytes, checksum_bits_len)
    if chk_bits == expected_chk:
        result["checksum_valid"] = True
    else:
        result["errors"].append("Checksum inválido: no coincide con SHA-256 de la entropía.")
        return result
    try:
        seed = try_lib_seed(cleaned, passphrase=passphrase)
        result["seed_sha256"] = hashlib.sha256(seed).hexdigest()
        result["seed_sha512"] = hashlib.sha512(seed).hexdigest()
    except Exception as e:
        result["errors"].append(f"Derivación de semilla fallida: {e}")
    return result

# From check_eth_balance.py
def check_eth_balance():
    RPC_ENDPOINTS = [
        "https://cloudflare-eth.com",
        "https://rpc.ankr.com/eth",
        "https://eth-mainnet.public.blastapi.io",
    ]
    address = input("Ingrese la dirección ETH a verificar: ").strip()
    print(f"[INFO] Consultando saldo de {address} en múltiples RPCs...\n")

    for rpc in RPC_ENDPOINTS:
        balance = get_balance(rpc, address)
        if balance is not None:
            print(f"[OK] {rpc} → {balance:.8f} ETH")
        else:
            print(f"[ERROR] {rpc} → sin respuesta")

def get_balance(rpc_url, address):
    try:
        payload = {
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [address, "latest"],
            "id": 1,
        }
        r = requests.post(rpc_url, json=payload, timeout=5)
        r.raise_for_status()
        data = r.json()
        if "result" in data:
            wei = int(data["result"], 16)
            eth = wei / 10**18
            return eth
    except Exception as e:
        return None
    return None

# From derive_addresses.py
def derive_addresses():
    # Implementación de Bech32 (BIP-173) en Python puro
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    def bech32_polymod(values):
        generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for value in values:
            top = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ value
            for i in range(5):
                chk ^= generator[i] if ((top >> i) & 1) else 0
        return chk

    def bech32_hrp_expand(hrp):
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

    def bech32_create_checksum(hrp, data):
        values = bech32_hrp_expand(hrp) + data
        polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
        return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

    def bech32_encode(hrp, data):
        combined = data + bech32_create_checksum(hrp, data)
        return hrp + '1' + "".join([CHARSET[d] for d in combined])

    def convertbits(data, frombits, tobits, pad=True):
        acc = 0
        bits = 0
        ret = []
        maxv = (1 << tobits) - 1
        for value in data:
            if value < 0 or (value >> frombits):
                return None
            acc = (acc << frombits) | value
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)
        if pad:
            if bits:
                ret.append((acc << (tobits - bits)) & maxv)
        elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
            return None
        return ret

    def pubkey_to_bech32_address(pubkey_compressed: bytes) -> str:
        sha_hash = hashlib.sha256(pubkey_compressed).digest()
        pubkeyhash = hashlib.new("ripemd160", sha_hash).digest()
        witness_program = [0x00] + list(pubkeyhash)
        data_5bit = convertbits(witness_program, 8, 5)
        return bech32_encode("bc", data_5bit)

    def process_phrases(phrases):
        results = []
        for phrase in phrases:
            seed_bytes = Bip39SeedGenerator(phrase).Generate(passphrase="")

            eth_master = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
            eth_node = eth_master.Purpose().Coin().Account(0).Change(0).AddressIndex(0)
            eth_addr = eth_node.PublicKey().ToAddress()

            btc_coin_def = {"purpose": 84, "coin_type": 0} # BIP84
            btc_master = Bip44.FromSeed(seed_bytes, btc_coin_def)
            btc_node = btc_master.Purpose().Coin().Account(0).Change(0).AddressIndex(0)
            btc_priv_key_bytes = btc_node.PrivateKey().Raw()._b
            btc_pubkey_compressed = privkey_to_pubkey_compressed(btc_priv_key_bytes)
            btc_addr = pubkey_to_bech32_address(btc_pubkey_compressed)

            results.append({
                "mnemonic": phrase,
                "eth_address": eth_addr,
                "btc_address": btc_addr
            })
        return results

    print("Seleccione una opción:")
    print("1) Agregar nuevas semillas y derivar direcciones")
    print("2) Usar archivo existente valid_seeds.json")
    choice = input("> ").strip()

    if choice == "1":
        phrases = []
        print("Ingrese frases semilla (12 palabras cada una). Escriba 'fin' para terminar:")
        while True:
            line = input("> ").strip()
            if line.lower() == "fin":
                break
            if line:
                phrases.append(line)
        results = process_phrases(phrases)
    else:
        input_path = os.path.join(BASE_DIR, "valid_seeds.json")
        with open(input_path, "r", encoding="utf-8") as f:
            phrases = json.load(f)
        results = process_phrases(phrases)

    output_path = os.path.join(BASE_DIR, "derived_addresses.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"✅ Se derivaron direcciones ETH y BTC de {len(results)} frases en {output_path}")



# From gen_addresses.py
def gen_addresses():
    print("[INFO] Generador de direcciones Ethereum desde semilla BIP39")
    mnemonic = input("Ingrese su frase semilla (12/24 palabras): ").strip()
    passphrase = ""  # MetaMask usa passphrase vacía por defecto

    # 1) Generar seed
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase=passphrase)
    print(f"[OK] Seed generada ({len(seed_bytes)} bytes)")

    # 2) Derivar con BIP44: Ethereum m/44'/60'/0'/0/n
    coin_def = Bip44Coins.ETHEREUM
    master = Bip44.FromSeed(seed_bytes, coin_def)

    for i in range(2):  # primeras dos direcciones
        node = master.Purpose().Coin().Account(0).Change(0).AddressIndex(i)
        priv_hex = node.PrivateKey().Raw().ToHex()
        addr = node.PublicKey().ToAddress()
        print(f"\n[#{i}]")
        print(f"Clave privada: {priv_hex}")
        print(f"Dirección ETH: {addr}")

# From gen_mnemonic_address.py
def gen_mnemonic_address():
    print("[INFO] Generando mnemonic (12 palabras) y primera dirección...")

    wordlist_path = "wordlist_english_clean.txt"
    if not os.path.exists(wordlist_path):
        print(f"[ERROR] No se encontró el archivo de wordlist: {wordlist_path}")
        return

    # Generar mnemonic de 12 palabras
    mnemo = Mnemonic("english", wordlist_path=wordlist_path)
    words = mnemo.generate(strength=128)  # 128 bits = 12 palabras
    if not mnemo.validate(words):
        print("[ERROR] Mnemonic inválido")
        return
    print(f"[OK] Mnemonic: {words}")

    # Generar seed
    seed_bytes = Bip39SeedGenerator(words).Generate(passphrase="")
    seed_hex = seed_bytes.hex()

    # Derivar primera dirección
    master = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
    acct0_0_0 = master.Purpose().Coin().Account(0).Change(0).AddressIndex(0)
    address = acct0_0_0.PublicKey().ToAddress()

    print(f"[OK] Address: {address}")

    # Guardar en JSON mnemonic y address
    data = {
        "mnemonic": words,
        "address": address
    }

    out_file = "mnemonic_address.json"
    with open(out_file, "w") as f:
        json.dump(data, f, indent=4)

    print(f"[INFO] Datos guardados en {out_file}")

# From test_rpc.py
def test_rpcs():
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"
    rpcs_file="rpcs.json"

    if not os.path.exists(rpcs_file):
        print(f"{RED}[ERROR]{RESET} No se encontró {rpcs_file}")
        return

    # Pedir dirección al usuario
    address = input("Ingresa la dirección a verificar: ").strip()
    if not address.startswith("0x") or len(address) < 20:
        print(f"{RED}[ERROR]{RESET} Dirección inválida")
        return

    with open(rpcs_file, "r") as f:
        rpcs = json.load(f)

    print("\n📊 Resultados del test RPC\n")
    print(f"{'Chain':25} | {'Estado':10} | {'Saldo (ETH)':15}")
    print("-"*55)

    for chain, url in rpcs.items():
        try:
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_getBalance",
                "params": [address, "latest"],
                "id": 1
            }
            resp = requests.post(url, json=payload, timeout=10)
            result = resp.json().get("result")
            if result:
                balance_wei = int(result, 16)
                balance_eth = balance_wei / 10**18
                estado = f"{GREEN}✔️ OK{RESET}"
                print(f"{chain:25} | {estado:10} | {balance_eth:.6f}")
            else:
                estado = f"{YELLOW}❌ FAIL{RESET}"
                print(f"{chain:25} | {estado:10} | {'-':15}")
        except Exception as e:
            estado = f"{RED}⚠️ ERROR{RESET}"
            print(f"{chain:25} | {estado:10} | {'-':15}")


def main_menu():
    while True:
        print("\nSeleccione una opción:")
        print("1. Generar nueva mnemonic y dirección")
        print("2. Generar direcciones desde una mnemonic existente")
        print("3. Derivar direcciones ETH y BTC desde mnemonic")
        print("4. Verificar saldo de dirección ETH")
        print("5. Probar RPCs")
        print("6. Salir")
        choice = input("> ").strip()

        if choice == "1":
            gen_mnemonic_address()
        elif choice == "2":
            gen_addresses()
        elif choice == "3":
            derive_addresses()
        elif choice == "4":
            check_eth_balance()
        elif choice == "5":
            test_rpcs()
        elif choice == "6":
            break
        else:
            print("Opción no válida.")

if __name__ == "__main__":
    main_menu()