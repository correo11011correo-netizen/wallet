#!/usr/bin/env python3
import json, requests, os

# Colores ANSI para mejorar la salida
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def test_rpcs(rpcs_file="proyecto/rpcs.json"):
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

if __name__ == "__main__":
    test_rpcs()
