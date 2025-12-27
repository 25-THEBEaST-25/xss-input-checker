import re

# Common XSS attack patterns
XSS_PATTERNS = [
    r"<script.*?>",
    r"javascript:",
    r"onerror=",
    r"onload=",
    r"<.*?on.*?>"
]

def is_malicious(user_input):
    for pattern in XSS_PATTERNS:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True
    return False

user_input = input("Enter input to test: ")

if is_malicious(user_input):
    print("⚠️ Potential XSS detected!")
else:
    print("✅ Input looks safe")
