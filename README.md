# Password_Analayzer
# Password Strength Analyzer

A Python-based Password Strength Analyzer that evaluates password security using multiple techniques such as entropy estimation, sequence detection, dictionary filtering, and brute-force simulation.

This project is designed for cybersecurity and digital forensics learning purposes and runs completely offline in the terminal without external dependencies.

---

## Features

- Password strength analysis
- Detects weak patterns
  - Sequential numbers (1234)
  - Sequential letters (abcd)
  - Repeated characters (aaaa)
- Dictionary attack filtering
- Dynamic charset calculation
- Entropy and combination estimation
- Brute-force attack simulation
- Strong password generator
- Security improvement suggestions
- Fully offline terminal application

---

## Technologies Used

- Python 3
- itertools
- time
- random
- string

---

## How It Works

The program analyzes a password by checking:

1. Password length
2. Character variety
3. Presence of:
   - Lowercase letters
   - Uppercase letters
   - Numbers
   - Symbols
4. Common dictionary words
5. Predictable sequences
6. Estimated brute-force combinations

The password is then classified into one of the following levels:

- Very Weak
- Weak
- Medium
- Strong
- Very Strong

---

## Installation

Clone the repository:

```bash
git clone https://github.com/your-username/password-strength-analyzer.git
