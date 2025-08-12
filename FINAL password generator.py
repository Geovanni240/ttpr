#!/usr/bin/env python3
"""
Bitwarden-like Password Generator (generator-only "dupe")
=========================================================

Minimal in-terminal menu
------------------------
Menu keys:
G: Generate now with current settings
L: Set length (8–20 characters)
C: Set count (# of passwords to generate)
J: Toggle JSON output
Q: Quit

Defaults (can be overridden via CLI flags):
- Uses lowercase, UPPERCASE, digits, symbols
- Avoids ambiguous characters (O/0, l/1/I)
- Human-proofing enabled (blocks sequences, repeats, keyboard walks, simple l33t)
- Requires at least one of each class
- Minimums: lower=3, upper=3, digits=3, symbols=3 (auto-capped if length is short)
- Length default: 20

Non-menu options are still available by flags (see --help).
"""
from __future__ import annotations
import argparse
import json
import math
import os
import re
import sys
from dataclasses import dataclass
from typing import List, Dict, Optional
from secrets import randbelow

# ---------------------------- Character Sets ----------------------------

LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"
SYMS   = "!@#$%^&*()-_=+[]{};:,.<>/?\\|`~"
AMBIGUOUS = set("O0oIl1|`'\";:.,{}[]()<>")

LEET_MAP = {
    'a': ['4', '@'],
    'e': ['3'],
    'i': ['1', '!'],
    'o': ['0'],
    's': ['5', '$'],
    't': ['7'],
    'g': ['9'],
    'b': ['8'],
}

COMMON_BAD_SUBSTRINGS = [
    "password","qwerty","letmein","admin","welcome","iloveyou","monkey",
    "dragon","login","abc","abcd","abc123","pass","guest","root","test",
]

QWERTY_ROWS = [
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
]

ADJ = {}
for row in QWERTY_ROWS:
    for i, ch in enumerate(row):
        neighbors = set()
        for j in range(max(0, i-2), min(len(row), i+3)):
            if j != i:
                neighbors.add(row[j])
        ADJ[ch] = neighbors
        ADJ[ch.upper()] = set(c.upper() for c in neighbors)

# ---------------------------- Utilities ----------------------------

def secure_choice(seq: str) -> str:
    return seq[randbelow(len(seq))]

def remove_ambiguous(s: str) -> str:
    return ''.join(ch for ch in s if ch not in AMBIGUOUS)

def has_sequence_run(pw: str, run_len: int = 4) -> bool:
    if len(pw) < run_len:
        return False
    def is_seq(a: str, b: str) -> bool:
        return (ord(b) - ord(a) == 1) or (ord(b) - ord(a) == -1)
    for i in range(len(pw)-run_len+1):
        segment = pw[i:i+run_len]
        asc = all(is_seq(segment[j], segment[j+1]) for j in range(run_len-1))
        if asc:
            return True
    return False

def has_repeated_runs(pw: str, run_len: int = 3) -> bool:
    if re.search(r'(.)\1{2,}', pw):
        return True
    for size in range(2, min(6, len(pw)//2 + 1)):
        block = pw[:size]
        if block * (len(pw)//size) == pw[:size*(len(pw)//size)] and len(pw) >= size*2:
            return True
    return False

def contains_common_bad_substrings(pw: str) -> bool:
    pw_l = pw.lower()
    return any(s in pw_l for s in COMMON_BAD_SUBSTRINGS)

def looks_like_keyboard_walk(pw: str, min_run: int = 4) -> bool:
    if len(pw) < min_run:
        return False
    walk_len = 1
    for a, b in zip(pw, pw[1:]):
        if b in ADJ.get(a, set()):
            walk_len += 1
            if walk_len >= min_run:
                return True
        else:
            walk_len = 1
    return False

def too_much_simple_leet(pw: str) -> bool:
    back = pw.lower()
    for k, vlist in LEET_MAP.items():
        for v in vlist:
            back = back.replace(v, k)
    return contains_common_bad_substrings(back)

def calc_entropy_bits(password: str, alphabet_size: int) -> float:
    return len(password) * math.log2(alphabet_size) if alphabet_size > 0 else 0.0

def estimated_alphabet_size(options) -> int:
    size = 0
    if options.lower: size += len(LOWER)
    if options.upper: size += len(UPPER)
    if options.digits: size += len(DIGITS)
    if options.symbols: size += len(SYMS)
    if options.no_ambiguous:
        size -= sum(1 for ch in (LOWER+UPPER+DIGITS+SYMS) if ch in AMBIGUOUS and (
            (options.lower and ch in LOWER) or
            (options.upper and ch in UPPER) or
            (options.digits and ch in DIGITS) or
            (options.symbols and ch in SYMS)
        ))
    return max(size, 0)

@dataclass
class Options:
    length: int = 20
    lower: bool = True
    upper: bool = True
    digits: bool = True
    symbols: bool = True
    no_ambiguous: bool = True
    human_proof: bool = True
    require_each_class: bool = True
    passphrase: bool = False
    words: int = 4
    sep: str = "-"
    count: int = 1
    json_out: bool = False
    # Minimum counts (sane strong defaults for menu mode)
    min_lower: int = 3
    min_upper: int = 3
    min_digits: int = 3
    min_symbols: int = 3
    # Exact mode (optional, still available via CLI)
    exact_mode: bool = False
    exact_lower: int = 0
    exact_upper: int = 0
    exact_digits: int = 0
    exact_symbols: int = 0

EMBED_WORDS = ["able","about","above","absorb","abstract","access","acid","acorn","across","action","actor","adapt",
    "add","adjust","admit","adult","advance","advice","aerobic","afford","afraid","after","again","agent",
    "agree","ahead","aim","air","alarm","album","alert","alley","alpha","alpine","also","alter","amber",
    "amuse","anchor","ancient","angel","angle","animal","ankle","answer","antenna","anvil","any","apart",
    "apple","april","arch","arena","argue","arise","armor","army","around","array","arrow","artist",
    "aspect","asset","assist","assume","athlete","atomic","attach","attack","attend","august","aunt",
    "author","auto","autumn","awake","award","axis","bacon","badge","bagel","balance","bamboo","banana","band","bank"]

def count_classes(pw: str) -> Dict[str, int]:
    lower = sum(1 for c in pw if c in LOWER)
    upper = sum(1 for c in pw if c in UPPER)
    digits = sum(1 for c in pw if c in DIGITS)
    symbols = sum(1 for c in pw if c in SYMS)
    other = len(pw) - (lower + upper + digits + symbols)
    return {"lower": lower, "upper": upper, "digits": digits, "symbols": symbols, "other": other}

# ------------------------ Generation Core ------------------------

def gen_password(opts: Options) -> str:
    if opts.passphrase:
        return gen_passphrase(opts)

    classes = []
    if opts.lower: classes.append(LOWER)
    if opts.upper: classes.append(UPPER)
    if opts.digits: classes.append(DIGITS)
    if opts.symbols: classes.append(SYMS)
    if not classes:
        raise ValueError("At least one character class must be enabled.")

    alphabet = ''.join(classes)
    if opts.no_ambiguous:
        alphabet = remove_ambiguous(alphabet)

    pool_lower = remove_ambiguous(LOWER) if opts.no_ambiguous else LOWER
    pool_upper = remove_ambiguous(UPPER) if opts.no_ambiguous else UPPER
    pool_digits = remove_ambiguous(DIGITS) if opts.no_ambiguous else DIGITS
    pool_symbols = remove_ambiguous(SYMS) if opts.no_ambiguous else SYMS

    if opts.exact_mode:
        total_exact = opts.exact_lower + opts.exact_upper + opts.exact_digits + opts.exact_symbols
        if total_exact != opts.length:
            raise ValueError("In --exact-mode the sum of exact counts must equal --length.")
        req_lower, req_upper, req_digits, req_symbols = opts.exact_lower, opts.exact_upper, opts.exact_digits, opts.exact_symbols
    else:
        req_lower = opts.min_lower + (1 if opts.require_each_class and opts.lower and opts.min_lower == 0 else 0)
        req_upper = opts.min_upper + (1 if opts.require_each_class and opts.upper and opts.min_upper == 0 else 0)
        req_digits = opts.min_digits + (1 if opts.require_each_class and opts.digits and opts.min_digits == 0 else 0)
        req_symbols = opts.min_symbols + (1 if opts.require_each_class and opts.symbols and opts.min_symbols == 0 else 0)
        if (req_lower + req_upper + req_digits + req_symbols) > opts.length:
            raise ValueError("Sum of required minimums exceeds length. Increase --length or lower mins.")

    for _ in range(4000):
        pw_chars = []

        for _ in range(req_lower):
            if opts.lower: pw_chars.append(secure_choice(pool_lower))
        for _ in range(req_upper):
            if opts.upper: pw_chars.append(secure_choice(pool_upper))
        for _ in range(req_digits):
            if opts.digits: pw_chars.append(secure_choice(pool_digits))
        for _ in range(req_symbols):
            if opts.symbols: pw_chars.append(secure_choice(pool_symbols))

        while len(pw_chars) < opts.length and not opts.exact_mode:
            pw_chars.append(secure_choice(alphabet))

        for i in range(len(pw_chars)-1, 0, -1):
            j = randbelow(i+1)
            pw_chars[i], pw_chars[j] = pw_chars[j], pw_chars[i]
        pw = ''.join(pw_chars)

        if opts.human_proof:
            if has_sequence_run(pw) or has_repeated_runs(pw) or contains_common_bad_substrings(pw) \
               or looks_like_keyboard_walk(pw) or too_much_simple_leet(pw):
                continue

        counts = count_classes(pw)
        if opts.exact_mode:
            if counts["lower"] != opts.exact_lower: continue
            if counts["upper"] != opts.exact_upper: continue
            if counts["digits"] != opts.exact_digits: continue
            if counts["symbols"] != opts.exact_symbols: continue
        else:
            if counts["lower"] < opts.min_lower: continue
            if counts["upper"] < opts.min_upper: continue
            if counts["digits"] < opts.min_digits: continue
            if counts["symbols"] < opts.min_symbols: continue

        return pw

    raise RuntimeError("Failed to generate a password that passes checks. Adjust options or length.")

def gen_passphrase(opts: Options) -> str:
    if opts.words < 3:
        raise ValueError("--words should be at least 3 for acceptable strength.")
    words = [secure_choice(EMBED_WORDS) for _ in range(opts.words)]
    for i, w in enumerate(words):
        if randbelow(2):
            words[i] = w[0].upper() + w[1:]
    separators = [opts.sep] * (len(words)-1)
    extra_pool = DIGITS + (SYMS if opts.symbols else "")
    if extra_pool:
        for i in range(len(separators)):
            if randbelow(3) == 0:
                separators[i] = secure_choice(extra_pool)
    out = []
    for i, w in enumerate(words):
        out.append(w)
        if i < len(separators):
            out.append(separators[i])
    return ''.join(out)

@dataclass
class Score:
    bits: float
    label: str
    warnings: List[str]

def score_password(pw: str, opts: Options) -> Score:
    alphabet_size = estimated_alphabet_size(opts) if not opts.passphrase else len(EMBED_WORDS) + len(DIGITS) + len(SYMS)
    bits = calc_entropy_bits(pw, alphabet_size)
    warnings = []
    penalty = 0.0
    if has_sequence_run(pw): 
        warnings.append("Contains straight sequences (e.g., abcd/1234).")
        penalty += 8
    if has_repeated_runs(pw):
        warnings.append("Contains repeated runs (e.g., aaa or abab).")
        penalty += 8
    if looks_like_keyboard_walk(pw):
        warnings.append("Looks like a keyboard walk (e.g., qwerty).")
        penalty += 12
    if contains_common_bad_substrings(pw):
        warnings.append("Contains common weak words (e.g., 'password', 'admin').")
        penalty += 14
    if too_much_simple_leet(pw):
        warnings.append("Simple l33t substitutions detected (e.g., 'p@ssw0rd').")
        penalty += 10
    variety = sum([bool(re.search(r'[a-z]', pw)),
                   bool(re.search(r'[A-Z]', pw)),
                   bool(re.search(r'[0-9]', pw)),
                   bool(re.search(r'[^a-zA-Z0-9]', pw))])
    if variety <= 2:
        warnings.append("Limited character variety; consider mixing cases, digits, and symbols.")
        penalty += 6
    adj_bits = max(bits - penalty, 0.0)
    if adj_bits < 50:
        label = "Weak"
    elif adj_bits < 70:
        label = "Fair"
    elif adj_bits < 90:
        label = "Strong"
    else:
        label = "Very Strong"
    return Score(bits=adj_bits, label=label, warnings=warnings)

def generate_and_report(opts: Options) -> List[dict]:
    out = []
    for _ in range(opts.count):
        pw = gen_password(opts)
        s = score_password(pw, opts)
        counts = count_classes(pw)
        out.append({
            "password": pw,
            "entropy_bits_estimate": round(s.bits, 1),
            "strength": s.label,
            "counts": counts,
            "warnings": s.warnings,
        })
    return out

# ------------------------ Minimal Menu ------------------------

def clear_screen():
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
    except Exception:
        pass

def render_settings(opts: Options) -> str:
    return (
        f"Length: {opts.length}  |  Count: {opts.count}\n"
        f"Ambiguous: {'avoid' if opts.no_ambiguous else 'allow'}  |  Human-proof: {'on' if opts.human_proof else 'off'}\n"
        f"Minimums -> lower:{opts.min_lower}  upper:{opts.min_upper}  digits:{opts.min_digits}  symbols:{opts.min_symbols}\n"
        f"JSON output: {'on' if opts.json_out else 'off'}"
    )

def prompt_int(msg: str, default: Optional[int]=None, min_val: int=1, max_val: Optional[int]=None) -> int:
    d = f" [{default}]" if default is not None else ""
    while True:
        ans = input(f"{msg}{d}: ").strip()
        if not ans and default is not None:
            return default
        try:
            v = int(ans)
            if v < min_val:
                print(f"Value must be >= {min_val}."); continue
            if max_val is not None and v > max_val:
                print(f"Value must be <= {max_val}."); continue
            return v
        except ValueError:
            print("Please enter an integer.")

def cap_minimums_to_length(opts: Options) -> None:
    """Ensure sum of minimums fits in current length by capping each to floor(length/4), min 1."""
    cap = max(1, opts.length // 4)
    opts.min_lower  = min(opts.min_lower, cap)
    opts.min_upper  = min(opts.min_upper, cap)
    opts.min_digits = min(opts.min_digits, cap)
    opts.min_symbols= min(opts.min_symbols, cap)
    while (opts.min_lower + opts.min_upper + opts.min_digits + opts.min_symbols) > opts.length and cap > 1:
        cap -= 1
        opts.min_lower  = min(opts.min_lower, cap)
        opts.min_upper  = min(opts.min_upper, cap)
        opts.min_digits = min(opts.min_digits, cap)
        opts.min_symbols= min(opts.min_symbols, cap)

def run_menu() -> Options:
    opts = Options()  # strong defaults
    while True:
        clear_screen()
        print("=== Password Generator (Minimal Menu) ===")
        print(render_settings(opts))
        print("\n[G]enerate  [L]ength (8–20)  [C]ount  [J]SON toggle  [Q]uit\n")

        choice = input("Select: ").strip().lower()
        if not choice:
            continue

        if choice == 'g':
            clear_screen()
            data = generate_and_report(opts)
            if opts.json_out:
                print(json.dumps(data, indent=2))
            else:
                for i, item in enumerate(data, 1):
                    print(f"[{i}] {item['password']}")
                    counts = item["counts"]
                    print(f"    Strength: {item['strength']}  |  Entropy (est.): {item['entropy_bits_estimate']} bits")
                    print(f"    Counts   - length: {len(item['password'])}, lower: {counts['lower']}, upper: {counts['upper']}, digits: {counts['digits']}, symbols: {counts['symbols']}, other: {counts['other']}")
                    if item["warnings"]:
                        print("    Warnings:")
                        for w in item["warnings"]:
                            print(f"      - {w}")
            input("\nPress Enter to return to menu...")
        elif choice == 'l':
            opts.length = prompt_int("Enter desired length (8–20)",
                                     default=min(max(opts.length, 8), 20),
                                     min_val=8, max_val=20)
            cap_minimums_to_length(opts)  # auto-cap mins to fit new length
        elif choice == 'c':
            opts.count = prompt_int("How many passwords to generate",
                                    default=opts.count, min_val=1, max_val=100)
        elif choice == 'j':
            opts.json_out = not opts.json_out
        elif choice == 'q':
            return opts
        else:
            continue

# ------------------------ CLI ------------------------

def parse_args(argv: List[str]) -> Options:
    # If no args, launch minimal menu by default
    if len(argv) == 0:
        return run_menu()

    p = argparse.ArgumentParser(description="Bitwarden-like password generator (generator-only).")
    p.add_argument("-L","--length", type=int, default=20, help="Password length (default: 20)")
    p.add_argument("-n","--count", type=int, default=1, help="How many passwords to generate (default: 1)")
    p.add_argument("--lower", action="store_true", help="Include lowercase letters")
    p.add_argument("--no-lower", dest="lower", action="store_false")
    p.add_argument("--upper", action="store_true", help="Include uppercase letters")
    p.add_argument("--no-upper", dest="upper", action="store_false")
    p.add_argument("--digits", action="store_true", help="Include digits")
    p.add_argument("--no-digits", dest="digits", action="store_false")
    p.add_argument("--symbols", action="store_true", help="Include symbols")
    p.add_argument("--no-symbols", dest="symbols", action="store_false")
    p.add_argument("--no-ambiguous", action="store_true", help="Avoid lookalike characters (O/0, l/1/I, etc.)")
    p.add_argument("--allow-ambiguous", dest="no_ambiguous", action="store_false")
    p.add_argument("--human-proof", action="store_true", help="Avoid common patterns and keyboard walks (default on)")
    p.add_argument("--no-human-proof", dest="human_proof", action="store_false")
    p.add_argument("--require-each-class", action="store_true", help="Require at least one of each selected class (default on)")
    p.add_argument("--no-require-each-class", dest="require_each_class", action="store_false")
    p.add_argument("--min-lower", type=int, default=3, help="Minimum lowercase letters required")
    p.add_argument("--min-upper", type=int, default=3, help="Minimum uppercase letters required")
    p.add_argument("--min-digits", type=int, default=3, help="Minimum digits required")
    p.add_argument("--min-symbols", type=int, default=3, help="Minimum symbols required")
    p.add_argument("--exact-mode", action="store_true", help="Use exact counts instead of minimums")
    p.add_argument("--exact-lower", type=int, default=0, help="Exact lowercase count (requires --exact-mode)")
    p.add_argument("--exact-upper", type=int, default=0, help="Exact uppercase count (requires --exact-mode)")
    p.add_argument("--exact-digits", type=int, default=0, help="Exact digits count (requires --exact-mode)")
    p.add_argument("--exact-symbols", type=int, default=0, help="Exact symbols count (requires --exact-mode)")
    p.add_argument("--json", dest="json_out", action="store_true", help="Emit JSON output")
    p.add_argument("--menu", action="store_true", help="Launch minimal menu")

    p.set_defaults(lower=True, upper=True, digits=True, symbols=True,
                   no_ambiguous=True, human_proof=True, require_each_class=True)
    args = p.parse_args(argv)

    if args.menu:
        return run_menu()

    opts = Options(length=args.length, lower=args.lower, upper=args.upper, digits=args.digits,
                   symbols=args.symbols, no_ambiguous=args.no_ambiguous, human_proof=args.human_proof,
                   require_each_class=args.require_each_class, count=args.count, json_out=args.json_out,
                   min_lower=args.min_lower, min_upper=args.min_upper, min_digits=args.min_digits, min_symbols=args.min_symbols,
                   exact_mode=args.exact_mode, exact_lower=args.exact_lower, exact_upper=args.exact_upper,
                   exact_digits=args.exact_digits, exact_symbols=args.exact_symbols)
    return opts

def main(argv: List[str]) -> int:
    try:
        opts = parse_args(argv)
        if opts.passphrase:
            data = []
            for _ in range(opts.count):
                pw = gen_passphrase(opts)
                s = score_password(pw, opts)
                counts = count_classes(pw)
                data.append({
                    "password": pw,
                    "entropy_bits_estimate": round(s.bits, 1),
                    "strength": "Passphrase (estimation)",
                    "counts": counts,
                    "warnings": s.warnings
                })
        else:
            data = generate_and_report(opts)

        if opts.json_out:
            print(json.dumps(data, indent=2))
        else:
            for i, item in enumerate(data, 1):
                print(f"[{i}] {item['password']}")
                counts = item["counts"]
                print(f"    Strength: {item['strength']}  |  Entropy (est.): {item['entropy_bits_estimate']} bits")
                print(f"    Counts   - length: {len(item['password'])}, lower: {counts['lower']}, upper: {counts['upper']}, digits: {counts['digits']}, symbols: {counts['symbols']}, other: {counts['other']}")
                if item["warnings"]:
                    print("    Warnings:")
                    for w in item["warnings"]:
                        print(f"      - {w}")
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
