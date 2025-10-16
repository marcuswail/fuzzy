#!/usr/bin/env python3
import argparse, json, sys

p = argparse.ArgumentParser(
    description="Avvolge ogni riga tra virgolette con virgola finale, oppure genera un array JSON valido."
)
p.add_argument("input", help="File .txt di input (una stringa per riga)")
p.add_argument("-o", "--out", help="File di output (default: stdout)")
p.add_argument("--array", action="store_true",
               help="Emetti un array JSON valido (senza virgola finale per l'ultimo elemento)")
p.add_argument("--keep-empty", action="store_true",
               help="Mantieni anche le righe vuote come stringhe vuote")
args = p.parse_args()

with open(args.input, encoding="utf-8") as f:
    lines = [ln.rstrip("\r\n") for ln in f]

if not args.keep_empty:
    lines = [ln for ln in lines if ln.strip() != ""]

# json.dumps gestisce automaticamente tutte le escape (virgolette, backslash, ecc.)
if args.array:
    output = json.dumps(lines, ensure_ascii=False)
else:
    output = "".join(f"{json.dumps(ln, ensure_ascii=False)},\n" for ln in lines)

if args.out:
    with open(args.out, "w", encoding="utf-8") as fo:
        fo.write(output)
else:
    sys.stdout.write(output)