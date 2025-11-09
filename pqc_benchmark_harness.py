
#!/usr/bin/env python3
"""
pqc_benchmark_harness.py
Beginner-friendly harness that logs benchmark results to a CSV compatible with the analysis notebook.

USAGE (synthetic data for a dry run):
  python pqc_benchmark_harness.py --out /path/to/pqc_perf_data.csv \
      --algs ML-KEM ML-DSA SPHINCS+ \
      --params 512 768 1024 \
      --ops keygen encap decap sign verify \
      --concurrency 1 16 64 256 \
      --message-bytes 0 1024 \
      --repeats 5

Later, replace the synthetic_timing() function with real measurements from your PQC library.
"""

import argparse
import csv
import os
import random
import time
from datetime import datetime
import platform
from pathlib import Path

def detect_env():
    """Collect simple environment info for reproducibility."""
    try:
        cpu_ghz = None
        # Try to estimate CPU GHz from Python (approximate)
        import subprocess, re
        if platform.system() == "Darwin":
            out = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"]).decode()
            # GHz often appears in the brand string; we won't parse aggressively
        elif platform.system() == "Linux":
            with open("/proc/cpuinfo","r") as f:
                for line in f:
                    if "cpu MHz" in line:
                        mhz = float(line.split(":")[1].strip())
                        cpu_ghz = round(mhz/1000.0, 2)
                        break
        elif platform.system() == "Windows":
            # Best effort; users on Windows can fill this manually
            pass
    except Exception:
        cpu_ghz = None

    # Basic flags (user can edit later if known)
    env = {
        "machine_id": os.environ.get("MACHINE_ID", platform.node() or "machine"),
        "os_name": platform.system().lower(),
        "containerized": int(os.environ.get("CONTAINERIZED", "0")),
        "cpu_ghz": cpu_ghz if cpu_ghz is not None else 0.0,
        "aesni": int(os.environ.get("AESNI", "0")),
        "avx2": int(os.environ.get("AVX2", "0")),
        "neon": int(os.environ.get("NEON", "0")),
    }
    return env

def ensure_header(path):
    """Write CSV header if the file doesn't exist or is empty."""
    header = [
        "alg_family","param_set","operation","message_bytes","concurrency",
        "cpu_ghz","aesni","avx2","neon","machine_id","os_name","containerized",
        "latency_ms","throughput_ops","timestamp","notes","trial_id"
    ]
    new_file = not Path(path).exists() or os.stat(path).st_size == 0
    if new_file:
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(header)

<<<<<<< HEAD
def try_import_oqs():
    try:
        import oqs
        return oqs
    except Exception:
        return None
    
def synthetic_timing(alg, param_set, operation, message_bytes, concurrency):
    """Return (latency_ms, throughput_ops) as a quick placeholder.
    This is *not* real crypto - just a randomized function to let you test the pipeline.
=======
def synthetic_timing(alg, param_set, operation, message_bytes, concurrency):
    """Return (latency_ms, throughput_ops) as a quick placeholder.
    This is *not* real crypto — just a randomized function to let you test the pipeline.
>>>>>>> 6755b76a1d5d63e5f0d7a89e5de5cda816dbf49d
    """
    base = {
        "ML-KEM": 10.0,
        "ML-DSA": 4.0,
        "SPHINCS+": 25.0
    }.get(alg, 12.0)

    # Heuristics to vary by op and size
    op_factor = {
        "keygen": 1.2,
        "encap": 1.0,
        "decap": 1.1,
        "sign": 1.5,
        "verify": 0.8
    }.get(operation, 1.0)

    size_factor = 1.0 + (message_bytes / 8192.0)  # small growth
    conc_factor = 1.0 + (concurrency / 512.0)     # more load => more latency

    # Randomness to emulate noise
    noise = random.normalvariate(0, 0.5)

    latency_ms = max(0.2, base * op_factor * size_factor * conc_factor + noise)
    throughput_ops = max(1.0, 1000.0 / latency_ms * (1.0 + random.uniform(-0.05, 0.05)))
    return latency_ms, throughput_ops

<<<<<<< HEAD
def resolve_oqs_name(oqs, user_name: str, is_sig: bool):
    """
    Map a user-supplied algorithm string (e.g., 'ML-KEM-768', 'Kyber768',
    'Dilithium3', 'Classic-McEliece-6688128') to an oqs mechanism name
    available in THIS build.

    Works with liboqs-python API variants that expose:
        - get_enabled_kem_mechanisms()
        - get_enabled_sig_mechanisms()
    """
    # 1) Pull available mechanisms for this build
    avail = (oqs.get_enabled_sig_mechanisms() if is_sig
             else oqs.get_enabled_kem_mechanisms())

    # 2) Exact match
    if user_name in avail:
        return user_name

    # 3) Case-insensitive match
    low_map = {a.lower(): a for a in avail}
    key = user_name.lower()
    if key in low_map:
        return low_map[key]

    # 4) Friendly aliases (both directions, since builds differ)
    aliases = {
        # Kyber / ML-KEM
        "Kyber512": "ML-KEM-512", "Kyber768": "ML-KEM-768", "Kyber1024": "ML-KEM-1024",
        "ML-KEM-512": "Kyber512", "ML-KEM-768": "Kyber768", "ML-KEM-1024": "Kyber1024",
        # Dilithium / ML-DSA
        "Dilithium2": "ML-DSA-44", "Dilithium3": "ML-DSA-65", "Dilithium5": "ML-DSA-87",
        "ML-DSA-44": "Dilithium2", "ML-DSA-65": "Dilithium3", "ML-DSA-87": "Dilithium5",
        # SPHINCS+ common variants (adjust if your build uses different names)
        "SPHINCS+-SHA2-128f-simple": "SPHINCS+-SHA2-128f",
        "SPHINCS+-SHA2-128s-simple": "SPHINCS+-SHA2-128s",
        "SPHINCS+-SHA2-128f": "SPHINCS+-SHA2-128f-simple",
        "SPHINCS+-SHA2-128s": "SPHINCS+-SHA2-128s-simple",
    }
    if user_name in aliases and aliases[user_name] in avail:
        return aliases[user_name]

    # 5) Substring fallback (best-effort)
    norm = user_name.replace("_", "-").lower()
    for a in avail:
        if norm in a.lower():
            return a

    return None  # caller can decide how to handle (e.g., fallback to synthetic)

def real_timing_bindings(alg, param_set, operation, message_bytes, concurrency, oqs):
    # Decide whether we’re dealing with a signature or a KEM based on the op
    is_sig = operation in ("sign", "verify")

    # If the user passed a family like "ML-DSA" + "65", form "ML-DSA-65".
    # If they passed a full mechanism (e.g., "Dilithium3"), leave as-is.
    candidate = f"{alg}-{param_set}" if param_set else alg

    oqs_name = resolve_oqs_name(oqs, candidate, is_sig)
    if oqs_name is None:
        raise ValueError(f"Cannot resolve algorithm name '{alg} {param_set}' for operation '{operation}'")

    import time
    start = time.perf_counter()

    if is_sig:
        with oqs.Signature(oqs_name) as sig:
            pk = sig.generate_keypair()
            msg = b"x" * int(message_bytes)
            if operation == "sign":
                _ = sig.sign(msg)
            else:
                signature = sig.sign(msg)
                _ = sig.verify(msg, signature, pk)
    else:
        with oqs.KeyEncapsulation(oqs_name) as kem:
            if operation == "keygen":
                kem.generate_keypair()
            elif operation == "encap":
                kem.generate_keypair()
                _ = kem.encap_secret()
            elif operation == "decap":
                kem.generate_keypair()
                ct, _ = kem.encap_secret()
                _ = kem.decap_secret(ct)
            else:
                raise ValueError(f"Unsupported KEM operation: {operation}")

    latency_ms = (time.perf_counter() - start) * 1000.0
    throughput_ops = 1000.0 / latency_ms if latency_ms > 0 else 0.0
=======
def real_timing_bindings(alg,param_set,operation,message_bytes,concurrency,oqs):
    is_sig=operation in ("sign","verify")
    oqs_name=resolve_oqs_name(oqs, f"{alg}-{param_set}" if alg.startswith("ML-") and param_set else alg, is_sig)
    if oqs_name is None: oqs_name=resolve_oqs_name(oqs, alg, is_sig)
    if oqs_name is None: raise ValueError(f"Cannot resolve algorithm name '{alg} {param_set}'")
    start=time.perf_counter()
    if operation in ("keygen","encap","decap"):
        with oqs.KeyEncapsulation(oqs_name) as kem:
            if operation=="keygen": kem.generate_keypair()
            elif operation=="encap": kem.generate_keypair(); kem.encap_secret()
            else: kem.generate_keypair(); ct, _ = kem.encap_secret(); kem.decap_secret(ct)
    elif operation in ("sign","verify"):
        with oqs.Signature(oqs_name) as sig:
            pk=sig.generate_keypair(); msg=b"x"*message_bytes
            if operation=="sign": sig.sign(msg)
            else: sig.verify(msg, sig.sign(msg), pk)
    else: raise ValueError("Unknown operation: "+operation)
    latency_ms=(time.perf_counter()-start)*1000.0
    throughput_ops=1000.0/latency_ms if latency_ms>0 else 0.0
>>>>>>> 6755b76a1d5d63e5f0d7a89e5de5cda816dbf49d
    return latency_ms, throughput_ops

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=str, required=True, help="Output CSV path (will be created if missing)")
<<<<<<< HEAD
    parser.add_argument("--mode", default="auto", choices=["auto", "real", "synthetic"],
                        help="real = use oqs bindings, synthetic = no oqs, auto = detect if oqs installed")
=======
>>>>>>> 6755b76a1d5d63e5f0d7a89e5de5cda816dbf49d
    parser.add_argument("--algs", nargs="+", default=["ML-KEM","ML-DSA","SPHINCS+"], help="Algorithm families")
    parser.add_argument("--params", nargs="+", default=["512","768","1024"], help="Parameter sets per algorithm")
    parser.add_argument("--ops", nargs="+", default=["keygen","encap","decap","sign","verify"], help="Operations")
    parser.add_argument("--concurrency", nargs="+", type=int, default=[1,16,64,256], help="Concurrency levels")
    parser.add_argument("--message-bytes", nargs="+", type=int, default=[0,1024], help="Payload sizes for applicable ops")
    parser.add_argument("--repeats", type=int, default=5, help="Trials per configuration")
    parser.add_argument("--notes", type=str, default="", help="Optional note to include on each row")

    args = parser.parse_args()
    env = detect_env()
    out_path = args.out
    ensure_header(out_path)
    oqs_module=try_import_oqs(); 
    use_real=(args.mode=="real") or (args.mode=="auto" and oqs_module is not None)
    trial_id = 0
    with open(out_path, "a", newline="") as f:
        writer = csv.writer(f)
        for alg in args.algs:
            for param in args.params:
                for op in args.ops:
                    for size in args.message_bytes:
                        for conc in args.concurrency:
                            # Warm-up discard pattern (synthetic): call once and ignore
                            # _ = synthetic_timing(alg, param, op, size, conc)
<<<<<<< HEAD
                            try:
                                _ = real_timing_bindings(alg,param,op,size,conc,oqs_module) if use_real else synthetic_timing(alg,param,op,size,conc)
=======
                            _ = real_timing_bindings(alg,param,op,size,conc,oqs_module) if use_real else synthetic_timing(alg,param,op,size,conc)
>>>>>>> 6755b76a1d5d63e5f0d7a89e5de5cda816dbf49d
                            except Exception: _ = synthetic_timing(alg,param,op,size,conc);
                            for r in range(args.repeats):
                                trial_id += 1
                                latency_ms, throughput_ops = synthetic_timing(alg, param, op, size, conc)
                                ts = datetime.utcnow().isoformat()
                                row = [
                                    alg, param, op, size, conc,
                                    env["cpu_ghz"], env["aesni"], env["avx2"], env["neon"],
                                    env["machine_id"], env["os_name"], env["containerized"],
                                    round(latency_ms, 4), round(throughput_ops, 2), ts, args.notes, trial_id
                                ]
                                writer.writerow(row)

    print(f"Done. Appended {trial_id} rows to {out_path}")

if __name__ == "__main__":
    main()
