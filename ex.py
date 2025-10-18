from pwn import *
from concurrent.futures import ThreadPoolExecutor
import threading
import json
import logging
from tqdm import tqdm
import random

def select_mode():
    print("seleziona la modalita' di fuzzing")
    print("1) modalità base") 
    print("2) modalità ramificata")
    while True:
        choice = int(input())
        if choice==1 or choice ==2:
            #base
            fuzz(all_payloads, choice)
        
        else: 
            print("riprova")


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

exe = './vuln1'
#elf = context.binary = ELF(exe, checksec=False)

with open('pays.json', 'r') as file:
    payloads = json.load(file)
    all_payloads = payloads['payloads']
    common_payloads = payloads['common_payloads']

#print(all_payloads)

lock = threading.Lock()
total_sent = 0 #contatore per numero di payloads mandati

# --- contatori crash/result ---
GOOD_TERM = 0
SEGMENTATION_FAULT = 0
ABORT = 0
ILLEGAL_INSTRUCTION = 0  
SIGTRAP = 0
FORCED_TERM = 0
OTHER = 0  # per i code positivi

'''
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
'''

def find_error(code_number):
    global GOOD_TERM, SEGMENTATION_FAULT, ABORT, ILLEGAL_INSTRUCTION, SIGTRAP, FORCED_TERM, OTHER
    if code_number == 0:
        with lock:
            GOOD_TERM += 1
        return 'GOOD_TERM'
    elif code_number == -11:   # SIGSEGV
        with lock:
            SEGMENTATION_FAULT += 1
        return 'SEGMENTATION_FAULT'
    elif code_number == -6:    # SIGABRT
        with lock:
            ABORT += 1
        return 'ABORT'
    elif code_number == -4:    # SIGILL
        with lock:
            ILLEGAL_INSTRUCTION += 1
        return 'ILLEGAL_INSTRUCTION'
    elif code_number == -5:    # SIGTRAP
        with lock:
            SIGTRAP += 1
        return 'SIGTRAP'
    elif code_number == -9:    # SIGKILL
        with lock:
            FORCED_TERM += 1
        return 'FORCED_TERM'
    else:
        with lock:
            OTHER += 1
        return 'OTHER'

def receiver_sender(payloads, pbar=None, pbar_lock=None):
    global total_sent
    try:
        logging.getLogger('pwnlib').setLevel(logging.CRITICAL)
        io = process([exe])
        pid = io.proc.pid
        while True:
            try:    
                prompt = io.recvrepeat(timeout=0.5)
            except EOFError:
                code = io.poll()
                
                #print(f"[!] Program exited after {counter} inputs")
                
                return {'code': code,'name': find_error(io.poll()), 'payload' : payloads,'pid':pid}
            except Exception as e:
                code = io.poll()
                
                return {'code':code,'name': find_error(io.poll()), 'payload' : payloads,'pid':pid}
            # se il programma non risponde al nostro input, rimane in hang
            
            if not prompt and io.poll() is None: #se è non il programma è in esecuione quindi è rimasto in stallo 
                try: 
                    #print("rimasto fermo, programma verrà killato con sigkill pid:", pid )
                    io.close()
                except Exception: 
                    
                    return {'code':code,'name': find_error(io.poll()), 'payload' : payloads,'pid':pid}
            #print(prompt.decode(errors='ignore'))
            io.sendline(payloads.encode()) #converte in bytes
            #print(f"sent: {payloads}")
            with lock:
                total_sent += 1
    except EOFError:
        code = io.poll()
        
        return {'code':code,'name': find_error(io.poll()), 'payload' : payloads,'pid':pid}
    except Exception as e:
        code = io.poll()
        
        return {'code':code,'name': find_error(io.poll()), 'payload' : payloads,'pid':pid}
    finally:
        io.close()
        if pbar and pbar_lock:
            with pbar_lock:
                pbar.update(1)
    

def receive_sender_pro(payloads, pbar=None, pbar_lock=None):
    global total_sent
    try:
        logging.getLogger('pwnlib').setLevel(logging.CRITICAL)
        io = process([exe])
        pid = io.proc.pid
        domanda_precedente = ""
        while True:
            try:    
                prompt = io.recvrepeat(timeout=0.5)
                if prompt == domanda_precedente:
                    invio = random.choice(common_payloads.encode())
                    print(invio)
                    io.sendline(invio)
                    
                    continue


            except EOFError:
                code = io.poll()
                
                #print(f"[!] Program exited after {counter} inputs")
                
                return {'code': code,'name': find_error(io.poll()), 'payload' : payloads,'pid':pid}
            except Exception as e:
                code = io.poll()
                
                return {'code':code,'name': find_error(io.poll()), 'payload' : payloads,'pid':pid}
            # se il programma non risponde al nostro input, rimane in hang
            
            if not prompt and io.poll() is None: #se è non il programma è in esecuione quindi è rimasto in stallo 
                try: 
                    #print("rimasto fermo, programma verrà killato con sigkill pid:", pid )
                    io.close()
                except Exception: 
                    
                    return {'code':code,'name': find_error(io.poll()), 'payload' : payloads,'pid':pid}
            #print(prompt.decode(errors='ignore'))
            io.sendline(payloads.encode()) #converte in bytes
            #print(f"sent: {payloads}")
            with lock:
                total_sent += 1
            domanda_precedente=prompt

    except EOFError:
        code = io.poll()
        
            
        return {'code':code,'name': find_error(io.poll()), 'payload' : payloads,'pid':pid}
    except Exception as e:
        code = io.poll()
        
        return {'code':code,'name': find_error(io.poll()), 'payload' : payloads,'pid':pid}
    finally:
        io.close()
        if pbar and pbar_lock:
            with pbar_lock:
                pbar.update(1)


def fuzz(payloads, choice):
    results = []
    number_of_payloads = len(payloads)
    print(f"number of payloads/process to start: {number_of_payloads}")
    
    pbar_lock = threading.Lock()
    with tqdm(total=number_of_payloads, desc='fuzzing', unit='payload') as pbar:
         
        with ThreadPoolExecutor(max_workers=80) as executor:
            if choice == 1:
                futures = [
                    executor.submit(receiver_sender, payload, pbar, pbar_lock)
                    for payload in payloads
                ]
            else:
                futures = [
                    executor.submit(receive_sender_pro, payload, pbar, pbar_lock) for payload in payloads


                ]

            for future in futures:
                results.append(future.result())
    return results

def print_results():
    print('=========================================')
    print(f'GOOD_TERM found: {GOOD_TERM}')
    print(f'SEGMENTATION_FAULT found: {SEGMENTATION_FAULT}')
    print(f'ABORT found: {ABORT}')
    print(f'ILLEGAL_INSTRUCTION found: {ILLEGAL_INSTRUCTION}')
    print(f'SIGTRAP found: {SIGTRAP}')
    print(f'FORCED_TERM found: {FORCED_TERM}')
    print(f'OTHER found: {OTHER}')
    print('-----------------------------------------')
    print(f'TOTAL SENT (lines): {total_sent}')
    print('=========================================')

 
#results = fuzz(all_payloads)

select_mode()
print(f"total payloads: {len(all_payloads)}")
print_results()
print(f'somma = {OTHER+ FORCED_TERM+ SIGTRAP+ ILLEGAL_INSTRUCTION+ ABORT+ SEGMENTATION_FAULT+ GOOD_TERM}')

