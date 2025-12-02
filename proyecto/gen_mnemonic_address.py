#!/usr/bin/env python3
# Genera un mnemonic de 12 palabras y la primera dirección (BIP39/BIP32/BIP44)
# Guarda mnemonic y address en un archivo JSON.
# No usar con fondos reales.

import os, json
from lib.mnemonic import Mnemonic
from lib.bip39seed import Bip39SeedGenerator
from lib.bip44coin import Bip44Coins
from lib.bip44 import Bip44

def main():
    print("[INFO] Generando mnemonic (12 palabras) y primera dirección...")

    wordlist_path = "proyecto/lib/wordlist_english_clean.txt"
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

    out_file = "proyecto/mnemonic_address.json"
    with open(out_file, "w") as f:
        json.dump(data, f, indent=4)

    print(f"[INFO] Datos guardados en {out_file}")

if __name__ == "__main__":
    main()
