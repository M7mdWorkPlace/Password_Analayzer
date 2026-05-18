import itertools  # Library used to generate all possible combinations for Brute-Force Demo
import time       # Library used to calculate the exact execution time of the crack process
import random     # Library used for generating random selections for the password generator
import string     # Library used to easily import character sets like lowercase, uppercase, and digits

# ═══════════════════════════════════════════════════════════════════════════
#   Password Strength Checker + Brute-Force Demo + Dictionary Attack Filter
# ═══════════════════════════════════════════════════════════════════════════

def check_sequences(pw):
    """
     NOTE: This function checks if the password contains weak patterns
    such as repeated characters, sequential numbers, or alphabetical sequences.
    It returns True and the reason if a weak pattern is found.
    """
    pw_lower = pw.lower()
    
    # 1. Checks for constant character repetition (e.g., 'aaaa' or '1111')
    for i in range(len(pw) - 3):
        if pw[i] * 4 in pw:
            return True, "Repeated characters"

    # 2. Checks for sequential number patterns forward/backward (e.g., '1234' or '9876')
    digits_forward  = "01234567890"
    digits_backward = "09876543210"
    for i in range(len(pw_lower) - 3):
        sub = pw_lower[i:i+4]
        if sub in digits_forward or sub in digits_backward:
            return True, f"Sequential numbers '{sub}'"

    # 3. Checks for alphabetical character sequences forward/backward (e.g., 'abcd' or 'zyxw')
    alphabet_forward  = "abcdefghijklmnopqrstuvwxyz"
    alphabet_backward = "zyxwvutsrqponmlkjihgfedcba"
    for i in range(len(pw_lower) - 3):
        sub = pw_lower[i:i+4]
        if sub in alphabet_forward or sub in alphabet_backward:
            return True, f"Sequential letters '{sub}'"

    return False, ""


def check_dictionary(pw):
    """
     NOTE: This function performs a 'Dictionary Attack Filter'.
    It converts the input password to lowercase and scans it against a list 
    of common words, famous names, local teams, and predictable keywords.
    """
    pw_lower = pw.lower()
    
    # Custom dictionary list containing popular and highly guessable words
    common_words = [
        "mohammed", "ahmed", "ali", "omar", "saud", "khaled", "ziyad", "abdullah",
        "saudi", "riyadh", "jeddah", "kuwait", "qatar", "dubai", "lebanon",
        "alahli", "alhilal", "alnassr", "ittihad", "ronaldo", "messi", "neymar",
        "kabsa", "shawarma", "burger", "pizza",
        "password", "admin", "welcome", "qwerty", "love" ,"didi" ,"asdfgh" ,"pmu", "2026" ,
    ]
    
    for word in common_words:
        if word in pw_lower:
            return True, f"Common word detected ('{word}')"
            
    return False, ""


def get_password():
    """
     NOTE: This function manages user input via a while-loop.
    It uses Python's built-in string methods to perform character-by-character analysis,
    validating the presence of lower, upper, digits, and special symbols.
    """
    print("=" * 52)
    print("  🔐  Password Strength Checker")
    print("=" * 52)
    while True:
        pw = input("\n  Enter your password: ")
        if len(pw) == 0:
            print("  ⚠️  Password is empty, try again.")
            continue

        # Using list comprehensions and built-in methods (.islower, .isupper, .isdigit, .isalnum)
        has_lower  = any(c.islower() for c in pw)
        has_upper  = any(c.isupper() for c in pw)
        has_digit  = any(c.isdigit() for c in pw)
        has_symbol = any(not c.isalnum() for c in pw)

        print("\n  📋  Password Analysis:")
        print(f"     {'✅' if has_lower  else '❌'}  Lowercase letters  (a-z)")
        print(f"     {'✅' if has_upper  else '❌'}  Uppercase letters  (A-Z)")
        print(f"     {'✅' if has_digit  else '❌'}  Numbers            (0-9)")
        print(f"     {'✅' if has_symbol else '❌'}  Symbols            (!@#$%^&*...)")

        missing = []
        if not has_lower:  missing.append("lowercase letters")
        if not has_upper:  missing.append("uppercase letters")
        if not has_digit:  missing.append("numbers")
        if not has_symbol: missing.append("symbols (!@#$...)")

        if missing:
            print(f"\n  ⚠️  Missing: {', '.join(missing)}")
            retry = input("  Try a different password? (y/n): ").strip().lower()
            if retry == "y":
                continue

        return pw


def build_charset(pw):
    """
     NOTE: This function creates a dynamic character set (Charset Pool).
    It extracts only the pools that match the user's password composition, which is
    essential for calculating accurate mathematical combinations.
    """
    charset = set()
    if any(c.islower() for c in pw): charset.update("abcdefghijklmnopqrstuvwxyz")
    if any(c.isupper() for c in pw): charset.update("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    if any(c.isdigit() for c in pw): charset.update("0123456789")
    for c in pw:
        if not c.isalnum():
            charset.add(c)
    return list(charset)


def strength_info(pw):
    """
     NOTE: This is the core logical engine. It evaluates entropy by raising
    the charset size to the power of length (cs_size ** length). It then combines entropy 
    with the results from our pattern and dictionary filters to classify the final safety level.
    """
    length     = len(pw)
    has_lower  = any(c.islower() for c in pw)
    has_upper  = any(c.isupper() for c in pw)
    has_digit  = any(c.isdigit() for c in pw)
    has_symbol = any(not c.isalnum() for c in pw)
    variety    = sum([has_lower, has_upper, has_digit, has_symbol])

    cs_size = 0
    if has_lower:  cs_size += 26
    if has_upper:  cs_size += 26
    if has_digit:  cs_size += 10
    if has_symbol: cs_size += 32
    total = cs_size ** length if cs_size else 0

    # Triggering the smart security filters
    is_pattern_weak, pattern_reason = check_sequences(pw)
    is_dict_weak, dict_reason       = check_dictionary(pw)

    # Main grading criteria workflow
    if length < 6 or variety == 1 or is_pattern_weak or is_dict_weak:
        label = "🔴 Very Weak"
        if is_pattern_weak:
            label += f" ({pattern_reason})"
        elif is_dict_weak:
            label += f" ({dict_reason})"
    elif length < 8 or variety == 2:
        label = "🟠 Weak"
    elif length < 12 and variety >= 3:
        label = "🟡 Medium"
    elif length < 16 and variety >= 3:
        label = "🟢 Strong"
    else:
        label = "🔵 Very Strong"

    return label, total, cs_size


def generate_strong_password(length=16):
    """
     NOTE: This acts as a utility to generate cryptographically safe structures.
    Using the 'random' library, it ensures at least 2 characters from every pool are present,
    then uses random.shuffle() to break any predictable ordering.
    """
    lower   = string.ascii_lowercase
    upper   = string.ascii_uppercase
    digits  = string.digits
    symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    pool    = lower + upper + digits + symbols
    
    # Guarantees compliance by hardcoding 2 items from each type first
    pwd = [
        random.choice(lower),  random.choice(lower),
        random.choice(upper),  random.choice(upper),
        random.choice(digits), random.choice(digits),
        random.choice(symbols),random.choice(symbols),
    ]
    # Fills the remaining requested length from the global pool
    pwd += [random.choice(pool) for _ in range(length - len(pwd))]
    random.shuffle(pwd)
    return "".join(pwd)


def suggest_strong_password(label):
    """
     NOTE: A user experience (UX) enhancement function.
    If the analyzed password falls below the secure thresholds, it presents 
    three newly generated high-entropy options as recommended alternatives.
    """
    if "Strong" in label and "Very Weak" not in label:   
        return
    print("\n" + "=" * 52)
    print("  💡  Your password is not strong enough!")
    print("     Here are 3 strong passwords you can use:")
    print("=" * 52)
    for i in range(3):
        print(f"  [{i+1}]  {generate_strong_password(16)}")
    print("=" * 52)
    print("  ✏️  Pick one, or use it as inspiration!")


def brute_force_demo(password, charset):
    """
     NOTE: A practical demonstration of a Brute-Force Attack.
    It uses 'itertools.product' to simulate computational permutations efficiently.
    To prevent systemic lockups, a guard rail is set to bypass passwords longer than 5 chars.
    Performance is clocked using 'time.perf_counter()'.
    """
    pw_len      = len(password)
    cs_size     = len(charset)
    total_combs = cs_size ** pw_len if cs_size else 0

    print(f"\n  🔓  Brute-Force Demo")
    print("  " + "─" * 48)

    if pw_len > 5:
        print(f"  Password length: {pw_len}  →  {total_combs:,} possible combinations")
        print("  ⏭️  Demo only runs on passwords ≤ 5 chars (would take too long).")
        return

    start = time.perf_counter()  # Captures start timestamp
    attempts = 0
    for length in range(1, pw_len + 1):
        for combo in itertools.product(charset, repeat=length):
            attempts += 1
            if "".join(combo) == password:
                elapsed = time.perf_counter() - start  # Measures execution delta time
                print(f"  ✅  Cracked after  {attempts:,}  attempts")
                print(f"  ⏱️   Time taken   :  {elapsed:.4f} seconds")
                return
    print(f"  ❌  Not found after {attempts:,} attempts.")


def main():
    """
     NOTE: The primary execution routine (Main Workflow Pipeline).
    It orchestrates the application state, binds data outputs from calculations,
    and runs the dynamic feedback engine.
    """
    pw                  = get_password()
    charset             = build_charset(pw)
    label, total, cs_sz = strength_info(pw)

    print("\n" + "=" * 52)
    print(f"  Password       :  {pw}")
    print(f"  Length         :  {len(pw)} characters")
    print(f"  Charset size   :  {cs_sz} unique symbols")
    print(f"  Combinations   :  {total:,}")
    print(f"  Strength       :  {label}")
    print("=" * 52)

    brute_force_demo(pw, charset)
    
    # OUTPUT TIPS INTERACTION: Dynamically matches feedback with calculated flaws
    print("\n  💡  Quick Security Tips:")
    if len(pw) < 12:
        print("      - Make your password longer (12+ characters is highly recommended).")
    if cs_sz < 50:
        print("      - Mix more uppercase letters, numbers, or symbols to expand the charset.")
        
    if "Common word" in label:
        extracted_word = label.split("'")[1] if "'" in label else "the word you used"
        print(f"      - Avoid using common dictionary words or names like '{extracted_word}'.")
    if "Sequential" in label:
        extracted_seq = label.split("'")[1] if "'" in label else "the patterns you used"
        print(f"      - Avoid predictable and sequential sequences like '{extracted_seq}'.")
        
    print("  " + "─" * 48)

    suggest_strong_password(label)

    print("\n  ✅  Done.\n")


if __name__ == "__main__":
    main()