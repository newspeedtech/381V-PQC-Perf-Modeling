
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
import traceback

def _detect_accel_flags():
    """
    Detect AESNI, AVX2, NEON as best we can from the OS.

    Priority:
      1. Respect explicit env vars AESNI/AVX2/NEON if set.
      2. Otherwise, try to infer from CPU flags on macOS/Linux.
      3. Fallback to 0 if unsure.
    """
    # 1) Env overrides (if you set AESNI=1 etc., we trust that)
    aesni_env = os.environ.get("AESNI")
    avx2_env  = os.environ.get("AVX2")
    neon_env  = os.environ.get("NEON")

    aesni = int(aesni_env) if aesni_env is not None else None
    avx2  = int(avx2_env)  if avx2_env  is not None else None
    neon  = int(neon_env)  if neon_env  is not None else None

    system = platform.system()

    # 2) Auto-detect if not set by env
    try:
        if system == "Darwin":
            # macOS: use sysctl output
            out = subprocess.check_output(
                ["sysctl", "-a"], stderr=subprocess.DEVNULL
            ).decode("utf-8", errors="ignore").lower()

            # Intel Macs: look at machdep.cpu.features / leaf7_features
            if aesni is None:
                aesni = int(" aes " in out or " aes," in out)
            if avx2 is None:
                avx2 = int(" avx2 " in out or " avx2," in out)

            # NEON is for ARM; on Apple Silicon, cpu features lines contain "neon"
            if neon is None:
                neon = int(" neon " in out or " neon," in out)

        elif system == "Linux":
            # Linux: /proc/cpuinfo works for both x86 and ARM
            with open("/proc/cpuinfo", "r") as f:
                text = f.read().lower()

            # x86: look at 'flags'
            # ARM: look at 'features' / 'neon'
            if aesni is None:
                aesni = int(" aes " in text or " aes," in text)

            if avx2 is None:
                avx2 = int(" avx2 " in text or " avx2," in text)

            if neon is None:
                neon = int(" neon " in text or " asimd " in text)
        else:
            # Other OSes (Windows, etc.) – no auto-detect; fall through to defaults
            pass

    except Exception:
        # If detection fails for any reason, we'll just fill defaults below
        pass

    # 3) Fill any remaining Nones with 0
    if aesni is None:
        aesni = 0
    if avx2 is None:
        avx2 = 0
    if neon is None:
        neon = 0

    return aesni, avx2, neon

import subprocess

import os
import platform
import subprocess
import traceback
import re

def detect_env():
    """Collect simple environment info for reproducibility, with dynamic CPU feature detection."""
    cpu_ghz = 0.0
    try:
        if platform.system() == "Darwin":
            # Example: "Intel(R) Core(TM) i5-1038NG7 CPU @ 2.00GHz"
            out = subprocess.check_output(
                ["sysctl", "-n", "machdep.cpu.brand_string"]
            ).decode("utf-8", errors="ignore")
            m = re.search(r"@ ([0-9.]+)\s*GHz", out)
            if m:
                cpu_ghz = float(m.group(1))
        elif platform.system() == "Linux":
            with open("/proc/cpuinfo", "r") as f:
                for line in f:
                    if "cpu MHz" in line:
                        mhz = float(line.split(":")[1].strip())
                        cpu_ghz = round(mhz / 1000.0, 2)
                        break
        elif platform.system() == "Windows":
            # Best effort; users can override via env if they care
            pass
    except Exception:
        traceback.print_exc()

    aesni, avx2, neon = _detect_accel_flags()

    env = {
        "machine_id": os.environ.get("MACHINE_ID", platform.node() or "machine"),
        "os_name": platform.system().lower(),
        "containerized": int(os.environ.get("CONTAINERIZED", "0")),
        "cpu_ghz": cpu_ghz,
        "aesni": aesni,
        "avx2": avx2,
        "neon": neon,
    }
    return env

def ensure_header(path):
    """Write CSV header if the file doesn't exist or is empty."""
    header = [
        "algorithm","operation","message_bytes","concurrency",
        "cpu_ghz","aesni","avx2","neon","machine_id","os_name","containerized",
        "latency_ms","throughput_ops", "crypto_type",
        "correctness","timestamp","notes","trial_id",
    ]
    new_file = not Path(path).exists() or os.stat(path).st_size == 0
    if new_file:
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(header)

def try_import_oqs():
    try:
        import oqs
        return oqs
    except ImportError as e:
        print(f"[INFO] Could not import oqs: {e}")
        return None
    
def resolve_oqs_name(oqs, user_name: str, is_sig: bool):
    """
    Map a user-supplied algorithm string (e.g., 'ML-KEM-768', 'Kyber768',
    'Dilithium3', 'Classic-McEliece-6688128') to an oqs mechanism name
    available in THIS build.

    Works with liboqs-python API variants that expose:
        - get_enabled_kem_mechanisms()
        - get_enabled_sig_mechanisms()
    """
    # Pull available mechanisms for this build
    avail = (oqs.get_enabled_sig_mechanisms() if is_sig
             else oqs.get_enabled_kem_mechanisms())
    
    # Exact match
    if user_name in avail:
        return user_name

    # Case-insensitive match
    low_map = {a.lower(): a for a in avail}
    key = user_name.lower()
    if key in low_map:
        return low_map[key]

    # Friendly aliases (both directions, since builds differ)
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

    # Substring fallback (best-effort)
    norm = user_name.replace("_", "-").lower()
    for a in avail:
        if norm in a.lower():
            return a
    print("*********************RETURNING NONE*************")
    return None  # caller can decide how to handle (e.g., fallback to synthetic)

def real_timing_bindings(alg, operation, message_bytes, concurrency, oqs):
    alg = alg.strip()
    operation = operation.strip()
    print("DEBUG operation =", alg)
    
    # Decide whether we’re dealing with a signature or a KEM based on the op
    is_sig = operation in ("sign", "verify")
    crypto_type = "Signature" if is_sig else "KEM"
    #print("*********************CRYPTO_TYPE*************", crypto_type)

    # If the user passed a family like "ML-DSA" + "65", form "ML-DSA-65".
    # If they passed a full mechanism (e.g., "Dilithium3"), leave as-is.
    candidate = alg.strip()

    oqs_name = resolve_oqs_name(oqs, candidate, is_sig)
    print(f"[DBG]  resolved oqs_name={oqs_name!r}")
    
    if oqs_name is None:
        raise ValueError(f"Cannot resolve algorithm name '{alg}' for operation '{operation}'")

    import time
    start = time.perf_counter()

    if is_sig:
        with oqs.Signature(oqs_name) as sig:
            pk = sig.generate_keypair()
            msg = b"x" * int(message_bytes)
            if operation == "sign":
                signature = sig.sign(msg)
                correctness = sig.verify(msg, signature, pk)
            else:
                signature = sig.sign(msg)
                correctness = sig.verify(msg, signature, pk)
    else:
        with oqs.KeyEncapsulation(oqs_name) as kem:
            if operation == "keygen":
                _ = kem.generate_keypair()
                correctness = True
            elif operation == "encap":
                pk = kem.generate_keypair()
                _ = kem.encap_secret(pk)
                correctness = True
            elif operation == "decap":
                pk = kem.generate_keypair()
                ct, ss_enc = kem.encap_secret(pk)
                ss_dec = kem.decap_secret(ct)
                correctness = (ss_enc == ss_dec)
            else:
                print("DEBUG operation =", repr(operation))
                raise ValueError(f"Unsupported KEM operation: {operation}")

    latency_ms = (time.perf_counter() - start) * 1000.0
    throughput_ops = 1000.0 / latency_ms if latency_ms > 0 else 0.0

    return latency_ms, throughput_ops, crypto_type, correctness

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=str, required=True, help="Output CSV path (will be created if missing)")
    parser.add_argument("--mode", default="auto", choices=["auto", "real", "synthetic"],
                        help="real = use oqs bindings, synthetic = no oqs, auto = detect if oqs installed")
    parser.add_argument("--algs", nargs="+", default=["ML-KEM","ML-DSA","SPHINCS+"], help="Algorithm families")
    parser.add_argument("--ops", nargs="+", default=["keygen","encap","decap","sign","verify"], help="Operations")
    parser.add_argument("--concurrency", nargs="+", type=int, default=[1,16,64,256], help="Concurrency levels")
    parser.add_argument("--message-bytes", nargs="+", type=int, default=[0,1024], help="Payload sizes for applicable ops")
    parser.add_argument("--repeats", type=int, default=5, help="Trials per configuration")
    parser.add_argument("--notes", type=str, default="", help="Optional note to include on each row")

    args = parser.parse_args()
    print("args.ops =", args.ops)
    print(detect_env())
    env = detect_env()
    out_path = args.out
    ensure_header(out_path)
    oqs_module = try_import_oqs()
    if oqs_module is None:
        raise SystemExit("oqs library not available. Install liboqs-python before running this harness.") 
    use_real=(args.mode=="real") or (args.mode=="auto" and oqs_module is not None)
    trial_id = 0
    with open(out_path, "a", newline="") as f:
        writer = csv.writer(f)
        for alg in args.algs:
            for op in args.ops:
                op = op.strip()
                print("*********************IN MAIN OP*************", op)
                if not op:
                    continue
                for size in args.message_bytes:
                    for conc in args.concurrency:
                        #try:
                        #    _ = real_timing_bindings(alg,param,op,size,conc,oqs_module)
                        #except Exception: 
                        #    traceback.print_exc() 
                    
                        for r in range(args.repeats):
                            trial_id += 1
                            if use_real:
                                try:
                                    latency_ms, throughput_ops, crypto_type, correctness = real_timing_bindings(alg, op, size, conc, oqs_module)
                                    #print("*********************IN MAIN CRYPTO_TYPE*************", crypto_type)
                                except Exception:
                                    traceback.print_exc() 
                            else:
                                print("help")
                                
                            ts = datetime.utcnow().isoformat()
                            #print("*********************WRITING OP*************", op)
                            row = [
                                alg, op, size, conc,
                                env["cpu_ghz"], env["aesni"], env["avx2"], env["neon"],
                                env["machine_id"], env["os_name"], env["containerized"],
                                round(latency_ms, 4), round(throughput_ops, 2), crypto_type, correctness, 
                                ts, args.notes, trial_id,
                                    
                            ]
                            writer.writerow(row)

    print(f"Done. Appended {trial_id} rows to {out_path}")

if __name__ == "__main__":
    main()
