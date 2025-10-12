#!/usr/bin/env python3
"""
Fuzzer con ThreadPoolExecutor + pwntools.

- Ogni task apre un processo, invia 1 payload e salva output/error in ./logs/
- Limita la concorrenza con max_workers
- Supporta modalità 'flatten' o 'grouped'
"""

from pwn import *
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading, time, os, traceback, signal

# CONFIG
exe = "./vuln1"             # binario target
MAX_WORKERS = 8             # numero massimo di processi concorrenti
LOG_DIR = "logs"            # dove salvare stdout/stderr/traceback
SEND_IMMEDIATELY = True     # True: invia subito senza aspettare prompt
RECV_TIMEOUT = 0.6          # tempo (sec) per recvrepeat

# PAYLOADS (usa i tuoi gruppi originali)
boolean_payloads = [
    b"yes", 
    b"no", 
    b"y", 
    b"n", 
    b"1", 
    b"2", 
    b"3", 
    b"A", 
    b"B", 
    b"C", 
    b"true", 
    b"false",
]
payloads = [
    b"%x", 
    b"%s", 
    b"%n", 
    b"%p", 
    b"%x %x %x", 
    b"%s %s %s", 
    b"%n %n %n", 
    b"%p %p %p",
    b"AAAA %x %x %x", 
    b"BBBB %s %s %s",
]
boundary_payloads = [
    b"A"*8, 
    b"A"*16, 
    b"A"*256, 
    b"A"*1024, 
    b"A"*10000, cyclic(100),
]
special_chars = [
    b"\x00", 
    b"\n\r", 
    b"\x0a\x0d", 
    b"'\"", b";|&`$", 
    b"../../../etc/passwd",
]
integer_payloads = [
    b"0", 
    b"-1", 
    b"2147483647", 
    b"2147483648", 
    b"-2147483648", 
    b"4294967295", 
    b"9999999999999",
]
command_injection = [
    b"; ls", 
    b"| cat /etc/passwd", 
    b"`whoami`", b"$(id)", 
    b"'; DROP TABLE users--",
]
unicode_payloads = [
    b"\xc0\x80", 
    b"\xff\xff\xff\xff", 
    "💣🔥".encode(), 
    "ＡＡＡＡ".encode(),
]
redos_payloads = [ b"a"*1000 + b"X", 
                  b"(" * 100 ]

# Metti i gruppi in una struttura
payload_groups = [
    boolean_payloads, payloads, boundary_payloads, special_chars,
    integer_payloads, command_injection, unicode_payloads, redos_payloads
]

# Helpers
os.makedirs(LOG_DIR, exist_ok=True)
for file in os.listdir(LOG_DIR):
    file_path = os.path.join(LOG_DIR, file)
    if os.path.isfile(file_path):
        os.remove(file_path)
global_counter_lock = threading.Lock()
global_counter = 0

#i thread incrementano il counter senza collisisoni
def next_id():
    global global_counter
    with global_counter_lock:
        global_counter += 1
        return global_counter

def worker_send_single(payload: bytes, id_gruppo: int, id_payload: int, send_immediately=True):
    """
    Invia un singolo payload e salva i log.
    Ritorna: {ok, run_id, group, index, out_path, err_path, meta{exitcode,signal,...}}
    """
########################################################################    
    run_id = next_id()
    fname_prefix = f"{run_id:06d}_g{id_gruppo}_i{id_payload}" 
    out_path = os.path.join(LOG_DIR, fname_prefix + ".out")
    err_path = os.path.join(LOG_DIR, fname_prefix + ".err")
    meta_path = os.path.join(LOG_DIR, fname_prefix + ".meta")
########################################################################
    result = {"run_id": run_id, "group": id_gruppo, "index": id_payload, "payload": repr(payload[:200]), "ok": False}
    
    try:
        io = process([exe])
        try:
            
            init = io.recvrepeat(timeout=RECV_TIMEOUT)
            io.sendline(payload)

            # raccogli un po' di output
            time.sleep(0.05)
            resp = io.recvrepeat(timeout=RECV_TIMEOUT)

            # prova ad aspettare che il processo termini (breve)
            # se il binario resta interattivo non fa nulla di male
            # poll() ritorna None se ancora vivo, altrimenti exit code (negativo = segnale)
            time.sleep(0.05)
            read_code = io.poll(block=False)  # pwntools: non blocca
            if read_code is None:
                # non è terminato: prova una micro attesa
                io.wait(timeout=0.1)
                read_code = io.poll(block=False)

            # salva stdout
            with open(out_path, "wb") as f:
                if init:
                    f.write(init)
                f.write(b"\n---RESPONSE---\n")
                if resp:
                    f.write(resp)

            # calcola segnale se read_code è negativo
            sig = None
            if isinstance(read_code, int):
                if read_code < 0:
                    sig = -read_code

            meta = {
                "pid": getattr(io, "proc", None) and getattr(io.proc, "pid", None),
                "payload_preview": repr(payload[:120]),
                "exit_code": read_code,
                "signal": sig,
                "init_len": len(init) if init else 0,
                "resp_len": len(resp) if resp else 0,
                "out_path": out_path,
                "err_path": err_path,
            }

            # Criterio di "ok": termina senza segnale (read_code is None o rc>=0)
            
            is_ok = (sig is None)
            result.update({"ok": is_ok, "meta": meta, "out_path": out_path, "err_path": err_path})

            # se crash, scrivi nota anche nel .err
            if not is_ok:
                with open(err_path, "a") as f:
                    f.write(f"Abnormal termination: exit_code={read_code}, signal={sig}\n")

        except EOFError:
            with open(err_path, "a") as f:
                f.write("EOFError: target closed connection\n")
            result.update({"ok": False, "error": "EOFError", "out_path": out_path, "err_path": err_path})
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            with open(err_path, "a") as f:
                f.write(tb)
            result.update({"ok": False, "error": str(e), "out_path": out_path, "err_path": err_path})
        finally:
            try:
                io.close()
            except Exception:
                pass
    except Exception:
        import traceback
        tb = traceback.format_exc()
        with open(err_path, "a") as f:
            f.write("Error launching process:\n")
            f.write(tb)
        result.update({"ok": False, "error": "launch_failed", "out_path": out_path, "err_path": err_path})

    # salva meta (sempre)
    try:
        with open(meta_path, "w") as f:
            f.write(str(result.get("meta", {})))
    except Exception:
        pass

    return result

def run(groups, max_workers=MAX_WORKERS, send_immediately=SEND_IMMEDIATELY):
    """Sottometti i task per gruppo (mantieni grouping)."""
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_to_task = {}
        for id_gruppo, group in enumerate(groups):
            for id_payload, payload in enumerate(group):
                fut = ex.submit(worker_send_single, payload, id_gruppo, id_gruppo, send_immediately)
                future_to_task[fut] = (id_gruppo, id_payload, payload)

        for fut in as_completed(future_to_task):
            task = future_to_task[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = {"ok": False, "error": str(e), "task": repr(task)}
            results.append(res)
            sig = (res.get("meta") or {}).get("signal")
            status = "CRASH" if sig else ("OK" if res.get("ok") else "FAIL")
            print(f"[grouped] done group={task[0]} idx={task[1]} -> {status} run_id={res.get('run_id')} sig={sig}")
    return results

# === Summarize helper ===
def _sig_name(sig_num):
    try:
        return signal.Signals(sig_num).name
    except Exception:
        return str(sig_num)

def summarize(results):
    per_signal = {}
    per_group_signal = {}
    ok_counter = 0

    for r in results:
        meta = r.get("meta") or {}
        sig = meta.get("signal")
        id_gruppo = r.get("group")
        if sig:
            key = _sig_name(sig)
            per_signal[key] = per_signal.get(key, 0) + 1
            if id_gruppo not in per_group_signal:
                per_group_signal[id_gruppo] = {}
            per_group_signal[id_gruppo][key] = per_group_signal[id_gruppo].get(key, 0) + 1
        else:
            if r.get("ok"):
                ok_counter += 1

    print("\n=== Summary ===")
    print(f"Total: {len(results)}  OK(no-signal): {ok_counter}  Crash: {sum(per_signal.values())}")
    if per_signal:
        print("By signal:")
        for s, c in sorted(per_signal.items(), key=lambda x: -x[1]):
            print(f"  {s}: {c}")
    if per_group_signal:
        print("By group & signal:")
        for gidid_gruppo, cnt in per_group_signal.items():
            if cnt:
                counts = ', '.join([f"{s}={c}" for s, c in sorted(cnt.items(), key=lambda x: -x[1])])
                print(f"  Group {id_gruppo}: {counts}")

if __name__ == "__main__":
    # Cambia qui la modalità se vuoi
    print("Starting fuzzer: max_workers=", MAX_WORKERS)

    results = run(payload_groups, max_workers=MAX_WORKERS, send_immediately=SEND_IMMEDIATELY)

    # Sintesi finale
    ok = sum(1 for r in results if r.get("ok"))
    print(f"Done. totale task: {len(results)} success: {ok} failed: {len(results)-ok}")
    print(f"Logs in ./{LOG_DIR}/")
    summarize(results)