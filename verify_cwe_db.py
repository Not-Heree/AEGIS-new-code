import json

with open(r'c:\Users\thapa\OneDrive\Pictures\EASM AEGIS project\easm code\data\cwe_remediation.json', 'r') as f:
    db = json.load(f)

print(f'✓ CWE Database Statistics:')
print(f'  Total CWEs: {len(db)}')
print(f'  Coverage: {len(db)}/1000+ CWE types ({100*len(db)/1000:.1f}%)')

# Analyze by category
categories = {}
for cwe_id, data in db.items():
    cat = data.get('category', 'unknown')
    categories[cat] = categories.get(cat, 0) + 1

print(f'\n✓ By Category:')
for cat in sorted(categories.keys()):
    print(f'  {cat}: {categories[cat]}')

# Sample CWEs
print(f'\n✓ Sample CWEs in database:')
sample_cwe = list(db.keys())[:8]
for cwe in sample_cwe:
    name = db[cwe]['name']
    print(f'  - {cwe}: {name[:50]}')
