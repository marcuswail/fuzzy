from pwn import *
from concurrent.futures import ThreadPoolExecutor
import threading


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


exe = './vuln1'
#elf = context.binary = ELF(exe, checksec=False)

# per domande booleane
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

# roba da mandare ad ogni richiesta di input
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
    b"%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x%x %x %x %x %x%x %x %x %x %x",
    b"%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s",
]

boundary_payloads = [
    b"A" * 8,           # Small overflow
    b"A" * 16,          # Medium
    b"A" * 256,         # Large
    b"A" * 1024,        # Very large
    b"A" * 10000,       # Huge
    cyclic(100),        # Pattern ciclico (per trovare offset)
]

special_chars = [
    b"\x00",            # Null byte
    b"\n\r",            # Newlines
    b"\x0a\x0d",        # CR/LF
    b"'\"",             # Quotes
    b";|&`$",           # Shell metacharacters
    b"../../../etc/passwd",  # Path traversal
]

integer_payloads = [
    b"0",
    b"-1",
    b"2147483647",      # INT_MAX (32-bit)
    b"2147483648",      # INT_MAX + 1
    b"-2147483648",     # INT_MIN
    b"4294967295",      # UINT_MAX
    b"9999999999999",   # Very large number
]

command_injection = [
    b"; ls",
    b"| cat /etc/passwd",
    b"`whoami`",
    b"$(id)",
    b"'; DROP TABLE users--",  # SQL injection
]

unicode_payloads = [
    b"\xc0\x80", b"\xff\xff\xff\xff", 
    "💣🔥".encode('utf-8', errors='ignore'), 
    "ＡＡＡＡ".encode('utf-8', errors='ignore'),
]

redos_payloads = [
    b"a" * 1000 + b"X",  # Pattern che causa backtracking
    b"(" * 100,          # Unbalanced parentheses
]

all_payloads = [unicode_payloads, boolean_payloads,integer_payloads, payloads, boundary_payloads, special_chars , command_injection, redos_payloads]

total_payloads = len(boolean_payloads) + len(payloads) + len(boundary_payloads) + len(special_chars) +len(integer_payloads) + len(command_injection)  + len(redos_payloads)

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
            io.sendline(payloads)
            #print(f"sent: {payloads.decode(errors='ignore')}")
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
        
        
        
    
    
for payloads in all_payloads:
    print(f"starting thread set for {payloads}")
    fuzz(payloads)
    



print(f"total: {total}")
print(f"total payloads: {total_payloads}")
