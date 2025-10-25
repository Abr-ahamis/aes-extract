#!/usr/bin/env python3
"""
aes_extract.py

Decrypts pyAesCrypt `.aes` files and restores the original filename by removing the trailing `.aes`.
Supports:
 - single file:   python3 aes_extract.py -e file.zip.aes -p "password"
 - wordlist brute-force: python3 aes_extract.py -e file.zip.aes -w rockyou.txt
 - directory:    python3 aes_extract.py -d /path/to/dir -w rockyou.txt
Parallel cracking available with -P / --procs

Requires: pyAesCrypt (pip install pyAesCrypt)
"""
import argparse
import os
import sys
import tempfile
import shutil
from functools import partial
from multiprocessing import Pool, cpu_count
import pyAesCrypt

BUFFER_DEFAULT = 64 * 1024

def strip_aes_suffix(path):
    """Remove only one trailing '.aes' segment from the filename, preserving other extensions."""
    if path.lower().endswith('.aes'):
        return path[:-4]
    return path

def try_decrypt_to_tmp(enc_path, password, bufferSize):
    """
    Attempt to decrypt enc_path to a temp file using password.
    Returns (True, tmp_path) on success, (False, error_str) on failure.
    """
    tmpfd, tmpname = tempfile.mkstemp(prefix="aes_decrypt_")
    os.close(tmpfd)
    try:
        pyAesCrypt.decryptFile(enc_path, tmpname, password, bufferSize)
        # If decryptFile doesn't raise, it succeeded
        return True, tmpname
    except Exception as e:
        # cleanup partial file
        try:
            if os.path.exists(tmpname):
                os.remove(tmpname)
        except Exception:
            pass
        return False, str(e)

def brute_force_with_pool(enc_path, wordlist_path, out_path, bufferSize, procs):
    """
    Tries passwords from wordlist in parallel. Moves decrypted result to out_path on success.
    Returns found_password or None.
    """
    if procs <= 1:
        # simple sequential fallback
        with open(wordlist_path, "rb") as f:
            idx = 0
            for raw in f:
                try:
                    pw = raw.rstrip(b"\r\n")
                    if not pw:
                        continue
                    try:
                        pw_str = pw.decode('utf-8')
                    except Exception:
                        pw_str = pw.decode('latin-1', errors='ignore')
                    idx += 1
                    if idx % 1000 == 0:
                        print(f"[+] Tried {idx} passwords; last: {pw_str[:30]}")
                    ok, info = try_decrypt_to_tmp(enc_path, pw_str, bufferSize)
                    if ok:
                        tmpname = info
                        shutil.move(tmpname, out_path)
                        print(f"[+] Success: password='{pw_str}' -> saved to {out_path}")
                        return pw_str
                except KeyboardInterrupt:
                    print("[!] Interrupted by user.")
                    return None
        return None

    # Parallel path
    # We'll stream batches to avoid reading the whole wordlist into memory.
    pool = Pool(processes=procs)
    try:
        def pw_generator():
            with open(wordlist_path, "rb") as f:
                for raw in f:
                    pw = raw.rstrip(b"\r\n")
                    if not pw:
                        continue
                    try:
                        yield pw.decode('utf-8')
                    except Exception:
                        yield pw.decode('latin-1', errors='ignore')

        batch_size = 256
        gen = pw_generator()
        tried = 0
        while True:
            batch = []
            try:
                for _ in range(batch_size):
                    batch.append(next(gen))
            except StopIteration:
                pass
            if not batch:
                break
            # map batch: each worker will attempt decryption and return (ok, value)
            results = pool.map(partial(try_decrypt_to_tmp, enc_path, bufferSize=bufferSize), batch)
            for pw, res in zip(batch, results):
                tried += 1
                ok, info = res
                if ok:
                    tmpname = info
                    try:
                        shutil.move(tmpname, out_path)
                    except Exception as e:
                        print("[!] Decrypted but failed to move file:", e)
                        print("[!] Temporary decrypted file is at:", tmpname)
                        pool.terminate()
                        pool.join()
                        return pw
                    pool.terminate()
                    pool.join()
                    print(f"[+] Success: password='{pw}' -> saved to {out_path}")
                    return pw
            # continue with next batch
        return None
    finally:
        try:
            pool.terminate()
            pool.join()
        except Exception:
            pass

def decrypt_with_password(enc_path, password, out_path, bufferSize):
    """Decrypt with a single known password and write to out_path"""
    ok, info = try_decrypt_to_tmp(enc_path, password, bufferSize)
    if ok:
        tmpname = info
        try:
            shutil.move(tmpname, out_path)
        except Exception as e:
            print("[!] Decrypted but failed to move file:", e)
            print("[!] Temporary decrypted file is at:", tmpname)
            return False
        print(f"[+] Decrypted successfully to: {out_path}")
        return True
    else:
        print("[!] Decryption failed:", info)
        return False

def process_file(enc_path, args):
    enc_path = os.path.abspath(enc_path)
    if not os.path.isfile(enc_path):
        print(f"[!] File not found: {enc_path}")
        return

    if not enc_path.lower().endswith('.aes'):
        print(f"[!] Skipping (not .aes): {enc_path}")
        return

    outname = os.path.basename(strip_aes_suffix(enc_path))
    outdir = args.outdir or os.path.dirname(enc_path) or "."
    os.makedirs(outdir, exist_ok=True)
    out_path = os.path.join(outdir, outname)

    print(f"[+] Processing: {enc_path}")
    print(f"    -> output will be: {out_path}")

    # If out_path exists, warn and skip unless --force
    if os.path.exists(out_path) and not args.force:
        print(f"[!] Output already exists: {out_path} (use --force to overwrite). Skipping.")
        return

    if args.password:
        success = decrypt_with_password(enc_path, args.password, out_path, args.buffer)
        if success:
            return
        else:
            print("[!] Provided password failed.")
            return

    if args.wordlist:
        if not os.path.isfile(args.wordlist):
            print("[!] Wordlist not found:", args.wordlist)
            return
        print(f"[+] Brute-forcing using wordlist: {args.wordlist} (procs={args.procs})")
        found = brute_force_with_pool(enc_path, args.wordlist, out_path, args.buffer, args.procs)
        if found:
            print(f"[+] Password found: {found}")
            return
        else:
            print("[!] Password NOT found for:", enc_path)
            # remove any partially created out_path
            if os.path.exists(out_path):
                try:
                    os.remove(out_path)
                except Exception:
                    pass
            return

    print("[!] No password or wordlist provided. Nothing done for:", enc_path)

def discover_aes_files(directory):
    out = []
    for root, _, files in os.walk(directory):
        for f in files:
            if f.lower().endswith('.aes'):
                out.append(os.path.join(root, f))
    return out

def main():
    ap = argparse.ArgumentParser(description="Decrypt pyAesCrypt .aes files and restore original name.")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--enc", help="Encrypted file (e.g. file.zip.aes)")
    group.add_argument("-d", "--dir", help="Directory to search for .aes files (recursive)")
    ap.add_argument("-w", "--wordlist", help="Wordlist file (one password per line) to brute-force")
    ap.add_argument("-p", "--password", help="Single password to try")
    ap.add_argument("-o", "--outdir", help="Directory to place decrypted outputs (default: same as enc file)")
    ap.add_argument("-b", "--buffer", type=int, default=BUFFER_DEFAULT, help=f"pyAesCrypt buffer size (default {BUFFER_DEFAULT})")
    ap.add_argument("-P", "--procs", type=int, default=max(1, cpu_count() - 1), help="Number of parallel workers for brute-force (default: cpu_count-1)")
    ap.add_argument("--force", action="store_true", help="Overwrite existing output files")
    args = ap.parse_args()

    # normalize procs
    args.procs = max(1, int(args.procs))

    targets = []
    if args.enc:
        targets = [args.enc]
    else:
        targets = discover_aes_files(args.dir)
        if not targets:
            print("[!] No .aes files found in directory.")
            return

    for t in targets:
        try:
            process_file(t, args)
        except KeyboardInterrupt:
            print("[!] Interrupted by user. Exiting.")
            return
        except Exception as e:
            print(f"[!] Error processing {t}: {e}")

if __name__ == "__main__":
    main()
