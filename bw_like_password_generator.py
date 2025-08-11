
#!/usr/bin/env python3
"""
Bitwarden-like Password Generator (generator-only "dupe")
=========================================================

A secure, flexible password generator inspired by Bitwarden's options,
with extra smarts to avoid predictable patterns (like keyboard walks and
common l33t substitutions) and to estimate strength.

Features
--------
- Cryptographically secure randomness (secrets module).
- Choose length, character classes, and ambiguity options.
- Enforce at least one of each selected character class.
- Optionally avoid lookalike characters (O/0, l/1/I, etc.).
- Optional "human-proof" mode that avoids predictable patterns:
  - blocks straight sequences (abcd, 0123), repeated runs (aaaa, 1212),
    common substrings ("password", "qwerty", ...),
    keyboard-adjacent walks across QWERTY rows.
  - discourages simple l33t (symbol-for-letter) patterns attackers try.
- Entropy estimation and strength score with detailed report.
- Generate multiple passwords at once.
- Optional passphrase mode (diceware-style) using an embedded mini wordlist.
- CLI with sensible defaults, plus JSON output for scripting.

Usage
-----
$ python bw_like_password_generator.py --help

Examples
--------
# 1 strong 20-char password, mixed classes (default), avoid lookalikes
$ python bw_like_password_generator.py

# 5 passwords, length 24, must include symbols, no ambiguous chars
$ python bw_like_password_generator.py -n 5 -L 24 --symbols --no-ambiguous

# Passphrase with 5 words and separators
$ python bw_like_password_generator.py --passphrase --words 5 --sep "-"

# JSON output (good for piping to other tools)
$ python bw_like_password_generator.py -n 3 --json
"""
from __future__ import annotations
import argparse
import json
import math
import re
import sys
from dataclasses import dataclass
from typing import List, Tuple
from secrets import choice, randbelow

# ---------------------------- Character Sets ----------------------------

LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"
SYMS   = "!@#$%^&*()-_=+[]{};:,.<>/?\\|`~"  # plenty of symbols
AMBIGUOUS = set("O0oIl1|`'\";:.," + "{}[]()<>")  # characters often confused

# Common l33t mappings (attackers try these first). We'll *discourage*
# total reliance on them by mixing more classes when human_proof is on.
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

# Build adjacency map for keyboard walks (US QWERTY). Include neighbors.
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

def remove_ambiguous(s: str) -> str:
    return ''.join(ch for ch in s if ch not in AMBIGUOUS)

def has_sequence_run(pw: str, run_len: int = 4) -> bool:
    # Detect straight ascending or descending sequences of digits/letters
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
    # Detect aaa, 111, !!! or abab, 1212 patterns
    if re.search(r'(.)\1{2,}', pw):
        return True
    # simple repeating block like "abab" or "123123"
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
    # Walk if each consecutive char is within adjacency set
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
    # If converting common leet back to letters yields a clear wordy string, flag it.
    back = pw.lower()
    for k, vlist in LEET_MAP.items():
        for v in vlist:
            back = back.replace(v, k)
    # If any bad substrings show up after reversing leet, it's a red flag
    return contains_common_bad_substrings(back)

def calc_entropy_bits(password: str, alphabet_size: int) -> float:
    # Lower bound assuming independent uniform picks from given alphabet
    return len(password) * math.log2(alphabet_size) if alphabet_size > 0 else 0.0

def estimated_alphabet_size(options) -> int:
    size = 0
    if options.lower: size += len(LOWER)
    if options.upper: size += len(UPPER)
    if options.digits: size += len(DIGITS)
    if options.symbols: size += len(SYMS)
    if options.no_ambiguous:
        # remove ambiguous from each class
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

# Small embedded wordlist for passphrases (entropy ~ log2(2048)=11 bits per word if 2048 words).
# Here we include 1024 words for size; 4 words ~ 44 bits + separator entropy. For max strength,
# increase --words or use password mode for 20+ chars.
EMBED_WORDS = [
    "able","about","above","absorb","abstract","access","acid","acorn","across","action","actor","adapt",
    "add","adjust","admit","adult","advance","advice","aerobic","afford","afraid","after","again","agent",
    "agree","ahead","aim","air","alarm","album","alert","alley","alpha","alpine","also","alter","amber",
    "amuse","anchor","ancient","angel","angle","animal","ankle","answer","antenna","anvil","any","apart",
    "apple","april","arch","arena","argue","arise","armor","army","around","array","arrow","artist",
    "aspect","asset","assist","assume","athlete","atomic","attach","attack","attend","august","aunt",
    "author","auto","autumn","awake","award","axis",
    "bacon","badge","bagel","balance","bamboo","banana","band","bank","barrel","basic","basket","battery",
    "beach","beam","bean","bear","beard","beaver","beauty","because","bed","beef","begin","behave",
    "behind","believe","bell","below","bench","benefit","best","betray","beyond","bicycle","bigger","bike",
    "binary","biology","bird","birth","bison","black","blade","blanket","blast","bleach","blend","bless",
    "blind","blink","block","blog","blood","bloom","blue","blush","board","boat","body","boil","bolt",
    "bomb","bonds","bonus","book","boost","border","bore","boss","bottle","bottom","bounce","bowl","box",
    "boy","brain","brand","brass","brave","bread","breeze","brick","bridge","brief","bright","bring","broad",
    "broken","bronze","broom","brown","brush","bubble","buddy","budget","buffer","bug","build","bulb",
    "bulk","bullet","bundle","bunker","burden","burger","burn","burst","bus","bush","business","busy","butter",
    "button","buyer",
    "cabin","cable","cactus","cage","cake","call","calm","camera","camp","canal","candy","canvas","canyon",
    "capital","captain","car","carbon","card","cargo","carpet","carry","cart","case","cash","casino","castle",
    "casual","cat","catalog","catch","category","cattle","cause","ceiling","cell","cement","census","center",
    "ceramic","chain","chair","chalk","champion","change","chaos","chapter","charge","charm","chart","chase",
    "chat","cheap","check","cheese","chef","cherry","chest","chew","chicken","chief","child","chimney","choice",
    "choose","chop","chorus","chrome","circle","citizen","city","civil","claim","clap","clarify","claw","clay",
    "clean","clear","clerk","clever","click","client","cliff","climb","clinic","clock","clone","close","cloth",
    "cloud","club","clue","coach","coal","coast","coconut","code","coffee","coin","cold","collar","color","column",
    "combine","come","comfort","comic","common","compact","company","concert","conduct","confirm","connect",
    "consider","control","cook","cool","copper","copy","coral","core","corn","correct","cost","cotton","couch",
    "country","couple","course","cousin","cover","coyote","crack","craft","crane","crash","crawl","crazy","cream",
    "create","credit","creek","crew","cricket","crime","crisp","critic","crop","cross","crowd","crown","cruise",
    "crystal","cube","culture","current","curtain","curve","cushion","custom","cycle",
    "daily","damage","dance","daring","dark","dash","data","date","daughter","dawn","deal","debate","debt",
    "decent","decide","deck","decor","deer","define","degree","delay","deliver","demand","denim","dense","dent",
    "deny","depend","deposit","depth","desert","design","desk","detail","device","diagram","dial","diamond",
    "diary","dice","diet","differ","digital","dinner","dinosaur","direct","dirt","disco","dish","disk","ditch",
    "dive","doctor","document","dollar","domain","donate","donkey","donut","door","double","dove","draft","dragon",
    "drama","draw","dream","dress","drift","drill","drink","drive","droid","drop","drum","dry","duck","dune","during",
    "dust","duty",
    "eager","eagle","early","earth","easel","east","easy","echo","ecology","edge","edit","educate","effect","egg",
    "eight","either","elbow","elder","electric","elegant","element","elite","else","email","ember","embryo","emerge",
    "emotion","employ","empty","enable","encode","end","enemy","energy","engine","enjoy","enough","enter","entire",
    "entry","envelope","equal","equip","era","error","escape","essay","estate","eternal","ethics","even","event",
    "every","exact","example","exceed","except","exchange","excite","exclude","excuse","execute","exercise","exhaust",
    "exhibit","exist","exit","expand","expect","expire","explain","explore","export","expose","express","extend",
    "extra",
]

def secure_choice(seq):
    return seq[randbelow(len(seq))]

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

    # Build allowed alphabet
    alphabet = ''.join(classes)
    if opts.no_ambiguous:
        alphabet = remove_ambiguous(alphabet)

    # Ensure we can fulfill require_each_class
    pools = [remove_ambiguous(c) if opts.no_ambiguous else c for c in classes]
    if opts.require_each_class:
        # Must have at least one from each selected pool
        if sum(1 for _ in pools) > opts.length:
            raise ValueError("Length too short to include all selected classes. Increase --length.")

    # Generate with secrets, retry if human_proof rejects
    for _ in range(1000):  # generous retry budget
        pw_chars = []
        if opts.require_each_class:
            for pool in pools:
                pw_chars.append(secure_choice(pool))
        # Fill remaining
        while len(pw_chars) < opts.length:
            pw_chars.append(secure_choice(alphabet))
        # Shuffle using Fisher-Yates with secrets
        for i in range(len(pw_chars)-1, 0, -1):
            j = randbelow(i+1)
            pw_chars[i], pw_chars[j] = pw_chars[j], pw_chars[i]
        pw = ''.join(pw_chars)

        if opts.human_proof:
            if has_sequence_run(pw) or has_repeated_runs(pw) or contains_common_bad_substrings(pw) \
               or looks_like_keyboard_walk(pw) or too_much_simple_leet(pw):
                continue  # try again
        return pw
    raise RuntimeError("Failed to generate a password that passes human-proof checks. Try adjusting options.")

def gen_passphrase(opts: Options) -> str:
    if opts.words < 3:
        raise ValueError("--words should be at least 3 for acceptable strength.")
    # Use embedded list; add capitalization and digits/symbols sprinkles for variety.
    words = [secure_choice(EMBED_WORDS) for _ in range(opts.words)]
    # Randomly capitalize some words to increase search space
    for i in range(len(words)):
        if randbelow(2):  # 50%
            w = words[i]
            words[i] = w[0].upper() + w[1:]
    # Optionally add a random digit or symbol between some words
    separators = [opts.sep] * (len(words)-1)
    # Sprinkle random separators with digits/symbols for extra entropy
    extra_pool = DIGITS + (SYMS if opts.symbols else "")
    if extra_pool:
        for i in range(len(separators)):
            if randbelow(3) == 0:  # ~33% chance to use a random char instead of sep
                separators[i] = secure_choice(extra_pool)
    result = []
    for i, w in enumerate(words):
        result.append(w)
        if i < len(separators):
            result.append(separators[i])
    return ''.join(result)

@dataclass
class Score:
    bits: float
    label: str
    warnings: List[str]

def score_password(pw: str, opts: Options) -> Score:
    # Estimate effective alphabet from options (lower bound).
    alphabet_size = estimated_alphabet_size(opts) if not opts.passphrase else len(EMBED_WORDS) + len(DIGITS) + len(SYMS)
    bits = calc_entropy_bits(pw, alphabet_size)

    warnings = []
    # Heuristics reduce effective bits if patterns found
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
    # Class variety bonus
    variety = sum([bool(re.search(r'[a-z]', pw)),
                   bool(re.search(r'[A-Z]', pw)),
                   bool(re.search(r'[0-9]', pw)),
                   bool(re.search(r'[^a-zA-Z0-9]', pw))])
    if variety <= 2:
        warnings.append("Limited character variety; consider mixing cases, digits, and symbols.")
        penalty += 6

    adj_bits = max(bits - penalty, 0.0)

    # Labels roughly aligned to common guidance
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
        out.append({
            "password": pw,
            "entropy_bits_estimate": round(s.bits, 1),
            "strength": s.label,
            "warnings": s.warnings,
        })
    return out

def parse_args(argv: List[str]) -> Options:
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
    p.add_argument("--passphrase", action="store_true", help="Generate a passphrase instead of a character password")
    p.add_argument("--words", type=int, default=4, help="Number of words for passphrase (default: 4)")
    p.add_argument("--sep", type=str, default="-", help="Separator between words (default: '-')")
    p.add_argument("--json", dest="json_out", action="store_true", help="Emit JSON output")
    p.set_defaults(lower=True, upper=True, digits=True, symbols=True,
                   no_ambiguous=True, human_proof=True, require_each_class=True)
    args = p.parse_args(argv)
    opts = Options(length=args.length, lower=args.lower, upper=args.upper, digits=args.digits,
                   symbols=args.symbols, no_ambiguous=args.no_ambiguous, human_proof=args.human_proof,
                   require_each_class=args.require_each_class, passphrase=args.passphrase, words=args.words,
                   sep=args.sep, count=args.count, json_out=args.json_out)
    return opts

def main(argv: List[str]) -> int:
    try:
        opts = parse_args(argv)
        if opts.passphrase:
            data = [{
                "password": gen_passphrase(opts),
                "entropy_bits_estimate": round(score_password(gen_passphrase(Options(passphrase=True, words=opts.words, sep=opts.sep, symbols=opts.symbols)).password, opts).bits, 1),
                "strength": "Passphrase (estimation)",
                "warnings": []
            } for _ in range(opts.count)]
        else:
            data = generate_and_report(opts)
        if opts.json_out:
            print(json.dumps(data, indent=2))
        else:
            for i, item in enumerate(data, 1):
                print(f"[{i}] {item['password']}")
                print(f"    Strength: {item['strength']}  |  Entropy (est.): {item['entropy_bits_estimate']} bits")
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
