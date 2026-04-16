import re
with open('app/services.py', 'r', encoding='utf-8') as f:
    content = f.read()

replacements = {
    r'\bcanonical_json\(': 'utils.canonical_json(',
    r'\bnew_id\(': 'utils.new_id(',
    r'\bsha256_hex\(': 'utils.sha256_hex(',
    r'\butc_now\(': 'utils.utc_now(',
    r'\butc_now_dt\(': 'utils.utc_now_dt('
}

for old, new in replacements.items():
    content = re.sub(old, new, content)

with open('app/services.py', 'w', encoding='utf-8') as f:
    f.write(content)
print("Done")
