from pwn import *
from concurrent.futures import ThreadPoolExecutor
import threading
import json




# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


exe = './vuln1'
#elf = context.binary = ELF(exe, checksec=False)

with open('payloads.json', 'r') as file:
    payloads = json.load(file)
    all_payloads = payloads['payloads']

print(all_payloads)

lock = threading.Lock()
total = 0 #contatore per numero di payloads mandati
summary_lock = threading.Lock()
crash_results = []
unique_crash_payloads = set()

def code_to_name(code):
    if code == 0:
        return 'OK'
    if code == 100:
        return 'EOF'
    if code == 101:
        return 'TIMEOUT_NO_PROMPT'
    if code == 102:
        return 'IO_ERROR'
    if code == 103:
        return 'UNEXPECTED_EXCEPTION'
    if code < 0:
        try:
            return f'SIGNAL_{signal.Signals(-code).name}'
        except Exception:
            return f'SIGNAL_{-code}'
    return f'EXIT_{code}'



def receiver_sender(payloads):
    global total
    try:
        io = process([exe])
        pid = io.proc.pid
        while True:
            try:    
                prompt = io.recvrepeat(timeout=0.5)
            except EOFError:
                #print(f"[!] Program exited after {counter} inputs")
                return {'code': io.poll(),'name': code_to_name(io.poll()), 'payload' : payloads,'pid':pid}
            except Exception as e:
                return {'code':io. poll(),'name': code_to_name(io.poll()), 'payload' : payloads,'pid':pid}
            # se il programma non risponde al nostro input, rimane in hang
            
            if not prompt and io.poll() is None: #se è non il programma è in esecuione quindi è rimasto in stallo 
                try: 
                    print("rimasto fermo, programma verrà killato con sigkill pid:", pid )
                    io.close()
                except Exception: 
                    return {'code':io. poll(),'name': code_to_name(io.poll()), 'payload' : payloads,'pid':pid}
            #print(prompt.decode(errors='ignore'))
            io.sendline(payloads.encode()) #converte in bytes
            print(f"sent: {payloads}")
            with lock:
                total += 1
    except EOFError:
        return {'code':io. poll(),'name': code_to_name(io.poll()), 'payload' : payloads,'pid':pid}
    except Exception as e:
        return {'code':io. poll(),'name': code_to_name(io.poll()), 'payload' : payloads,'pid':pid}
    finally:
        io.close()
    


def fuzz(payloads):
    results = []
    number_of_payloads = len(payloads)
    print(f"number of payloads/process to start: {number_of_payloads}")
    
    with ThreadPoolExecutor(max_workers=150) as executor:
        futures = [executor.submit(receiver_sender, payload) for payload in payloads]
        for future in futures:
            result = future.result()
            results.append(result)
    for exc in results:
        print(exc)
        
        
        
    
fuzz(all_payloads)
    



print(f"total: {total}")
print(f"total payloads: {len(all_payloads)}")
