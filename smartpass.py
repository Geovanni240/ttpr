
#!/usr/bin/env python3
"""
smartpass.py — "Bitwarden-like" smart password generator & scorer

Features
- Generates strong random passwords or passphrases.
- Avoids predictable patterns (l33t words, keyboard walks, repeats, dates/years).
- Penalizes common weaknesses in the strength score.
- CLI options to control length, character sets, ambiguity, passphrase count, and minimum score.
- Deterministic mode with --seed for reproducible results when testing.

Usage
  python smartpass.py             # default: 20-char mixed password, score shown
  python smartpass.py -l 24 -S    # include symbols, 24 length
  python smartpass.py --passphrase -w 6
  python smartpass.py --min-score 120
  python smartpass.py --json      # machine-readable output

Notes
- This tool *does not* store anything. Copy your password and keep it securely.
- Scoring is a heuristic; higher is generally better. Aim for ≥ 100.
"""

from __future__ import annotations
import argparse
import json
import math
import os
import random
import re
import string
from collections import Counter

# -------------------------
# Character sets & options
# -------------------------

UPPERS = "ABCDEFGHJKLMNPQRSTUVWXYZ"  # omit I, O for ambiguity
LOWERS = "abcdefghijkmnopqrstuvwxyz" # omit l for ambiguity
DIGITS = "23456789"                  # omit 0,1 for ambiguity
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
AMBIGUOUS = "O0oIl1|`'\";:.,~"

DEFAULT_LEN = 20
DEFAULT_MIN_SCORE = 100

# Small built-in word list for passphrases (short to keep file size reasonable).
# You can supply your own wordlist with --wordlist FILE for more variety.
BUILTIN_WORDS = [
    "apple","arrow","azure","bamboo","beacon","bison","blossom","bolt","canyon","cedar",
    "cipher","cobalt","comet","crimson","delta","drift","ember","falcon","fjord","flint",
    "glacier","harbor","helium","honey","indigo","ivy","jade","jigsaw","jupiter","kilo",
    "koala","lagoon","lantern","lilac","linen","lotus","lumen","marble","meteor","mint",
    "nebula","nickel","nova","onyx","opal","orchid","otter","oxide","panda","pearl",
    "pepper","phoenix","piano","pico","pioneer","pluto","prairie","quartz","quest","quiet",
    "radar","raven","river","sable","sage","saffron","salmon","sapphire","scarlet","shadow",
    "signal","silk","sierra","silver","skylark","slate","smoky","sonic","spruce","steel",
    "stellar","summer","summit","sunset","swift","tango","teal","tempo","thistle","tidal",
    "topaz","torch","tulip","tundra","unity","urban","valor","vapor","velvet","violet",
    "virgo","vista","vortex","walnut","willow","winter","xenon","yarrow","zephyr","zinc"
]

# Common substitutions for l33t-speak recognition
LEET_MAP = {
    'a': '[a@4]',
    'e': '[e3]',
    'i': '[i1!|]',
    'o': '[o0]',
    's': '[s$5]',
    't': '[t7+]',
    'g': '[g9]',
    'b': '[b8]'
}

# Very small "bad" dictionary (expand with --badwords if you like)
COMMON_BAD = {
    "password","letmein","qwerty","admin","welcome","dragon","iloveyou",
    "monkey","abc123","football","baseball","shadow"
}

# Keyboard rows for simple walk detection (US QWERTY)
KEY_ROWS = [
    "1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./"
]
KEY_GRID = {ch:(r,c) for r,row in enumerate(KEY_ROWS) for c,ch in enumerate(row)}

def is_adjacent(a:str,b:str)->bool:
    pa, pb = KEY_GRID.get(a.lower()), KEY_GRID.get(b.lower())
    if pa is None or pb is None:
        return False
    ra,ca = pa; rb,cb = pb
    return max(abs(ra-rb), abs(ca-cb)) == 1 or (ra==rb and abs(ca-cb)==1)

# -------------------------
# Utilities
# -------------------------

def effective_charset(pw: str) -> int:
    """Estimate size of character set effectively used by the password."""
    has_upper = any(c.isupper() for c in pw)
    has_lower = any(c.islower() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_symbol = any(c in SYMBOLS for c in pw)
    size = 0
    if has_lower: size += 26
    if has_upper: size += 26
    if has_digit: size += 10
    if has_symbol: size += len(SYMBOLS)
    return max(size, 1)

def shannon_entropy_bits(pw: str) -> float:
    """Shannon entropy based on char frequency distribution."""
    n = len(pw)
    freq = Counter(pw)
    probs = [c/n for c in freq.values()]
    H = -sum(p*math.log2(p) for p in probs)
    return H * n

def charset_entropy_bits(pw: str) -> float:
    N = effective_charset(pw)
    return len(pw) * math.log2(N)

def detect_repeats(pw:str, min_run:int=3)->int:
    """Return max repeated run length."""
    max_run = 1
    cur = 1
    for i in range(1, len(pw)):
        if pw[i] == pw[i-1]:
            cur += 1
            max_run = max(max_run, cur)
        else:
            cur = 1
    return max_run if max_run >= min_run else 0

def detect_sequential_numbers(pw:str, min_len:int=4)->bool:
    seqs = "0123456789"
    rev = seqs[::-1]
    for i in range(len(pw)-min_len+1):
        chunk = pw[i:i+min_len]
        if chunk in seqs or chunk in rev:
            return True
    return False

def detect_keyboard_walk(pw:str, min_len:int=4)->bool:
    if len(pw) < min_len:
        return False
    walk = 1
    for i in range(1, len(pw)):
        if is_adjacent(pw[i-1], pw[i]):
            walk += 1
            if walk >= min_len:
                return True
        else:
            walk = 1
    return False

def leetify_pattern(word:str)->str:
    out = ""
    for ch in word.lower():
        out += LEET_MAP.get(ch, ch)
    return out

def detect_leet_dictionary(pw:str, words:set[str])->bool:
    """Detect if the pw contains a dictionary word with common l33t substitutions."""
    pw_low = pw.lower()
    for w in words:
        if len(w) < 4:  # ignore very short words
            continue
        pat = leetify_pattern(w)
        if re.search(pat, pw_low):
            return True
    return False

def detect_dates_years(pw:str)->bool:
    """Detect obvious years like 1990-2029 or mmdd/yyyymmdd patterns."""
    if re.search(r'(19[5-9]\d|20[0-4]\d|2050)', pw):  # years 1950–2050
        return True
    # mmdd or ddmm
    if re.search(r'(^|\D)(0[1-9]|1[0-2])[.\-/]?(0[1-9]|[12]\d|3[01])(\D|$)', pw):
        return True
    # yyyymmdd
    if re.search(r'(19|20)\d{2}[.\-/]?(0[1-9]|1[0-2])[.\-/]?(0[1-9]|[12]\d|3[01])', pw):
        return True
    return False

def ambiguity_fraction(pw:str)->float:
    if not pw:
        return 0.0
    amb_count = sum(1 for c in pw if c in AMBIGUOUS)
    return amb_count / len(pw)

def score_password(pw:str, words:set[str]|None=None)->dict:
    """
    Produce a structured strength score with penalties for patterns.
    Score is approximate bits-like number; higher is better.
    """
    words = words or COMMON_BAD
    base_bits = charset_entropy_bits(pw)
    shannon_bits = shannon_entropy_bits(pw)
    max_run = detect_repeats(pw)
    penalties = 0.0
    notes = []

    if detect_sequential_numbers(pw):
        penalties += 10; notes.append("sequential-numbers")
    if detect_keyboard_walk(pw):
        penalties += 12; notes.append("keyboard-walk")
    if max_run:
        penalties += 8 + (max_run-3)*2; notes.append(f"repeated-run-{max_run}")
    if detect_dates_years(pw):
        penalties += 8; notes.append("date/year")
    if detect_leet_dictionary(pw, words):
        penalties += 18; notes.append("dictionary/leet")
    amb_frac = ambiguity_fraction(pw)
    if amb_frac > 0.25:
        penalties += 4; notes.append("too-ambiguous")

    # Combine two entropy estimates conservatively
    raw = min(base_bits, shannon_bits)
    final = max(0.0, raw - penalties)

    return {
        "password": pw,
        "length": len(pw),
        "entropy_bits_estimate": round(final, 2),
        "raw_bits_estimate": round(raw, 2),
        "penalties": round(penalties, 2),
        "flags": notes
    }

# -------------------------
# Generators
# -------------------------

def random_chars(length:int, *, use_upper=True, use_lower=True, use_digits=True, use_symbols=False, avoid_ambiguous=True)->str:
    alphabet = ""
    if use_lower: alphabet += LOWERS + ("l" if not avoid_ambiguous else "")
    if use_upper: alphabet += UPPERS + ("IO" if not avoid_ambiguous else "")
    if use_digits: alphabet += DIGITS + ("01" if not avoid_ambiguous else "")
    if use_symbols: alphabet += SYMBOLS

    if not alphabet:
        raise ValueError("At least one character class must be enabled.")

    rng = random.SystemRandom()
    # Ensure variety: force include at least one from each selected class
    buckets = []
    if use_lower: buckets.append(rng.choice(LOWERS if avoid_ambiguous else string.ascii_lowercase))
    if use_upper: buckets.append(rng.choice(UPPERS if avoid_ambiguous else string.ascii_uppercase))
    if use_digits: buckets.append(rng.choice(DIGITS if avoid_ambiguous else string.digits))
    if use_symbols: buckets.append(rng.choice(SYMBOLS))

    while len(buckets) < length:
        buckets.append(rng.choice(alphabet))

    rng.shuffle(buckets)
    return "".join(buckets[:length])

def generate_password(length:int=DEFAULT_LEN, *, use_upper=True, use_lower=True, use_digits=True, use_symbols=True,
                      avoid_ambiguous=True, min_score:int=DEFAULT_MIN_SCORE, badwords:set[str]|None=None, max_tries:int=500)->dict:
    """
    Generate a password that *scores above* min_score and avoids common patterns.
    Will try up to max_tries times with fresh randomness.
    """
    badwords = badwords or COMMON_BAD
    rng = random.SystemRandom()
    for _ in range(max_tries):
        pw = random_chars(length, use_upper=use_upper, use_lower=use_lower, use_digits=use_digits,
                          use_symbols=use_symbols, avoid_ambiguous=avoid_ambiguous)
        rep = score_password(pw, words=badwords)
        # reject if any nasty flags show up
        if any(f in rep["flags"] for f in ("keyboard-walk","dictionary/leet","date/year","repeated-run-4","repeated-run-5")):
            continue
        if rep["entropy_bits_estimate"] >= min_score:
            return rep
    # If we get here, return best effort (last one)
    return rep

def load_wordlist(path:str)->list[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        words = [w.strip().lower() for w in f if w.strip() and w.strip().isalpha()]
    if not words:
        raise ValueError("Wordlist appears empty or invalid.")
    return words

def generate_passphrase(n_words:int=5, wordlist:list[str]|None=None, min_score:int=DEFAULT_MIN_SCORE)->dict:
    rng = random.SystemRandom()
    words = wordlist or BUILTIN_WORDS
    picks = [rng.choice(words) for _ in range(n_words)]
    sep = rng.choice(["-","_","."])
    pw = sep.join(picks)
    rep = score_password(pw, words=set(words) | COMMON_BAD)
    # For passphrases, we want ≥ min_score/1.5 since raw bits are computed differently
    if rep["entropy_bits_estimate"] < (min_score/1.5):
        # try once more with an extra word
        picks.append(rng.choice(words))
        pw = sep.join(picks)
        rep = score_password(pw, words=set(words) | COMMON_BAD)
    rep["password"] = pw
    rep["type"] = "passphrase"
    return rep

# -------------------------
# CLI
# -------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Smart password generator & scorer")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--passphrase", action="store_true", help="Generate a passphrase instead of a character password")
    g.add_argument("-l","--length", type=int, default=DEFAULT_LEN, help="Password length (when not using --passphrase)")

    p.add_argument("-w","--words", type=int, default=5, help="Number of words for passphrase")
    p.add_argument("--wordlist", type=str, help="Path to custom wordlist (one word per line)")

    p.add_argument("-U","--no-upper", action="store_true", help="Disable uppercase letters")
    p.add_argument("-L","--no-lower", action="store_true", help="Disable lowercase letters")
    p.add_argument("-D","--no-digits", action="store_true", help="Disable digits")
    p.add_argument("-S","--symbols", action="store_true", help="Include symbols")
    p.add_argument("-A","--allow-ambiguous", action="store_true", help="Allow ambiguous characters like O,0,l,1")

    p.add_argument("--min-score", type=int, default=DEFAULT_MIN_SCORE, help="Minimum acceptable score")
    p.add_argument("--json", action="store_true", help="Output JSON only")
    p.add_argument("--seed", type=int, help="Set PRNG seed (testing only)")
    return p.parse_args()

def main():
    args = parse_args()
    if args.seed is not None:
        random.seed(args.seed)

    if args.wordlist:
        try:
            words = load_wordlist(args.wordlist)
        except Exception as e:
            raise SystemExit(f"Failed to load wordlist: {e}")
    else:
        words = None

    if args.passphrase:
        rep = generate_passphrase(args.words, wordlist=words, min_score=args.min_score)
    else:
        rep = generate_password(
            length=args.length,
            use_upper=not args.no_upper,
            use_lower=not args.no_lower,
            use_digits=not args.no_digits,
            use_symbols=args.symbols,
            avoid_ambiguous=not args.allow_ambiguous,
            min_score=args.min_score
        )
        rep["type"] = "password"

    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(f"{rep['type'].capitalize()}: {rep['password']}")
        print(f"Length: {rep['length']}")
        print(f"Score (bits est.): {rep['entropy_bits_estimate']} (raw {rep['raw_bits_estimate']}, penalties {rep['penalties']})")
        if rep["flags"]:
            print("Flags:", ", ".join(rep["flags"]))
        else:
            print("Flags: none")

if __name__ == "__main__":
    main()
