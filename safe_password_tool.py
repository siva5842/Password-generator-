#!/usr/bin/env python3
"""
Safe Password Utility (educational)
Checks password strength and generates secure random passwords.
"""

import secrets
import string
import argparse
import sys
from math import log2

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "111111", "123123",
    "qwerty", "abc123", "iloveyou", "admin", "welcome", "password1"
}

def entropy_estimate(password: str) -> float:
    charset_size = 0
    if any(c.islower() for c in password): charset_size += 26
    if any(c.isupper() for c in password): charset_size += 26
    if any(c.isdigit() for c in password): charset_size += 10
    if any(c in string.punctuation for c in password): charset_size += len(string.punctuation)
    if charset_size == 0: return 0.0
    return len(password) * log2(charset_size)

def score_password(password: str):
    reasons = []
    if not password:
        return 0, ["Password is empty."]
    length = len(password)
    ent = entropy_estimate(password)

    if password.lower() in COMMON_PASSWORDS:
        reasons.append("Password is a very common password (easily guessable).")
    if length < 8:
        reasons.append("Password is shorter than 8 characters — choose a longer password.")
    if not any(c.islower() for c in password):
        reasons.append("No lowercase letters found — include lowercase.")
    if not any(c.isupper() for c in password):
        reasons.append("No uppercase letters found — include uppercase.")
    if not any(c.isdigit() for c in password):
        reasons.append("No digits found — include numbers.")
    if not any(c in string.punctuation for c in password):
        reasons.append("No symbols/punctuation found — add symbols for stronger entropy.")
    if password.isalpha():
        reasons.append("Password is letters only — mix in digits & symbols.")
    if password.isdigit():
        reasons.append("Password is digits only — avoid using only numbers.")
    if length >= 20 and ent >= 100:
        reasons.append("Excellent length and entropy.")

    score = 0
    if length >= 16: score += 35
    else: score += int((length / 16) * 35)

    variety = 0
    if any(c.islower() for c in password): variety += 1
    if any(c.isupper() for c in password): variety += 1
    if any(c.isdigit() for c in password): variety += 1
    if any(c in string.punctuation for c in password): variety += 1
    score += int((variety / 4) * 35)
    score += min(30, int((ent / 140) * 30))

    if password.lower() in COMMON_PASSWORDS: score = max(0, score - 40)
    if length < 4: score = max(0, score - 30)

    score = max(0, min(100, score))

    label = "Very Weak"
    if score >= 90: label = "Excellent"
    elif score >= 75: label = "Strong"
    elif score >= 50: label = "Moderate"
    elif score >= 25: label = "Weak"

    reasons.insert(0, f"Estimated entropy: {ent:.1f} bits. Strength label: {label}.")
    return score, reasons

def generate_password(length: int = 16, use_symbols: bool = True) -> str:
    if length < 4: raise ValueError("Length should be at least 4.")
    alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits
    if use_symbols: alphabet += string.punctuation
    while True:
        pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and (not use_symbols or any(c in string.punctuation for c in pwd))):
            return pwd

def main():
    parser = argparse.ArgumentParser(description="Safe Password Utility — strength checker & generator (educational).")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", "-c", metavar="PASSWORD", help="Check the strength of PASSWORD")
    group.add_argument("--generate", "-g", action="store_true", help="Generate a strong password")
    parser.add_argument("--length", "-l", type=int, default=16, help="Length for generated password (default 16)")
    parser.add_argument("--no-symbols", action="store_true", help="Don't include symbols in generated password")
    args = parser.parse_args()

    if args.check:
        pwd = args.check
        score, reasons = score_password(pwd)
        print(f"Password checked: '{pwd}'")
        print(f"Score: {score}/100")
        for r in reasons: print(" -", r)
        if pwd.lower() in COMMON_PASSWORDS:
            print("WARNING: This password is on a small list of common passwords included for education.")
        sys.exit(0)

    if args.generate:
        pwd = generate_password(length=args.length, use_symbols=not args.no_symbols)
        print("Generated password:", pwd)
        score, reasons = score_password(pwd)
        print(f"Estimated strength: {score}/100")
        for r in reasons: print(" -", r)
        sys.exit(0)

    print("Safe Password Utility (interactive).")
    print("1) Check a password")
    print("2) Generate a strong password")
    choice = input("Choose (1/2): ").strip()
    if choice == "1":
        pwd = input("Enter password to check: ")
        score, reasons = score_password(pwd)
        print(f"\nScore: {score}/100")
        for r in reasons: print(" -", r)
    elif choice == "2":
        try: length = int(input("Length (recommended 12-24): ") or "16")
        except ValueError: length = 16
        pwd = generate_password(length=length, use_symbols=True)
        print("\nGenerated password:", pwd)
        score, reasons = score_password(pwd)
        print(f"Estimated strength: {score}/100")
        for r in reasons: print(" -", r)
    else:
        print("Exiting."); sys.exit(0)

if __name__ == "__main__": main()
