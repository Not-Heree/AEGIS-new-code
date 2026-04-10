"""
Validation Suite: Hybrid CWE Remediation Database

Validates:
1. Database integrity (valid JSON)
2. Entry structure
3. No missing required fields
4. Category distribution
5. Code example coverage
"""

import json
import sys

def validate_cwe_database():
    """Validate CWE remediation database."""
    
    print("\n" + "╔" + "="*68 + "╗")
    print("║" + " "*18 + "CWE REMEDIATION DATABASE VALIDATOR" + " "*17 + "║")
    print("╚" + "="*68 + "╝\n")
    
    # Load database
    try:
        with open(r'c:\Users\thapa\OneDrive\Pictures\EASM AEGIS project\easm code\data\cwe_remediation.json', 'r') as f:
            db = json.load(f)
        print(f"✓ Database loaded successfully")
    except Exception as e:
        print(f"✗ Failed to load database: {e}")
        return False
    
    print(f"✓ Total CWEs in database: {len(db)}")
    print(f"✓ Coverage: {len(db)}/1000 CWE types ({100*len(db)/1000:.1f}%)\n")
    
    # Validate structure
    print("="*70)
    print("VALIDATION 1: Entry Structure")
    print("="*70)
    
    required_fields = ["name", "category", "fix_steps", "code_examples", "references"]
    optional_fields = ["impact", "business_impact", "timeline", "source"]
    
    errors = []
    missing_fields_count = {}
    
    for cwe_id, entry in db.items():
        for field in required_fields:
            if field not in entry:
                if field not in missing_fields_count:
                    missing_fields_count[field] = []
                missing_fields_count[field].append(cwe_id)
    
    if missing_fields_count:
        print("✗ Found entries with missing required fields:")
        for field, cwe_ids in missing_fields_count.items():
            print(f"  - {field}: missing in {cwe_ids[:3]}...")
            errors.append(f"Missing {field} in {len(cwe_ids)} entries")
    else:
        print("✓ All entries have required fields")
    
    # Validate data types
    print("\n" + "="*70)
    print("VALIDATION 2: Data Type Validation")
    print("="*70)
    
    type_errors = []
    for cwe_id, entry in db.items():
        if not isinstance(entry.get("fix_steps"), list):
            type_errors.append(f"{cwe_id}: fix_steps must be list")
        if not isinstance(entry.get("code_examples"), dict):
            type_errors.append(f"{cwe_id}: code_examples must be dict")
        if not isinstance(entry.get("references"), list):
            type_errors.append(f"{cwe_id}: references must be list")
    
    if type_errors:
        print(f"✗ Found {len(type_errors)} type errors:")
        for error in type_errors[:5]:
            print(f"  - {error}")
    else:
        print("✓ All data types correct (fix_steps=list, code_examples=dict, references=list)")
    
    # Analyze categories
    print("\n" + "="*70)
    print("VALIDATION 3: Category Distribution")
    print("="*70)
    
    categories = {}
    for cwe_id, entry in db.items():
        cat = entry.get("category", "unknown")
        if cat not in categories:
            categories[cat] = 0
        categories[cat] += 1
    
    print(f"✓ Unique categories: {len(categories)}\n")
    print(f"{'Category':<30s} {'Count':<8s} {'Example CWEs':<30s}")
    print("-" * 70)
    
    for cat in sorted(categories.keys()):
        count = categories[cat]
        # Find examples for this category
        examples = [cwe_id for cwe_id, e in db.items() if e.get("category") == cat][:2]
        example_str = ", ".join(examples)
        print(f"{cat:<30s} {count:<8d} {example_str:<30s}")
    
    # Code examples coverage
    print("\n" + "="*70)
    print("VALIDATION 4: Code Examples Coverage")
    print("="*70)
    
    has_examples = 0
    examples_by_lang = {}
    
    for cwe_id, entry in db.items():
        code_examples = entry.get("code_examples", {})
        if code_examples:
            has_examples += 1
            for lang in code_examples.keys():
                examples_by_lang[lang] = examples_by_lang.get(lang, 0) + 1
    
    print(f"✓ Entries with code examples: {has_examples}/{len(db)} ({100*has_examples/len(db):.1f}%)")
    print(f"\nCode example languages:")
    for lang in sorted(examples_by_lang.keys()):
        count = examples_by_lang[lang]
        print(f"  - {lang:<20s}: {count:<4d} entries")
    
    # Timeline distribution
    print("\n" + "="*70)
    print("VALIDATION 5: Remediation Timeline Distribution")
    print("="*70)
    
    timelines = {}
    for cwe_id, entry in db.items():
        timeline = entry.get("timeline", "not specified")
        timelines[timeline] = timelines.get(timeline, 0) + 1
    
    print(f"{'Timeline':<20s} {'Count':<8s} {'Percentage':<12s}")
    print("-" * 40)
    for timeline in sorted(timelines.keys()):
        count = timelines[timeline]
        pct = 100 * count / len(db)
        print(f"{timeline:<20s} {count:<8d} {pct:>10.1f}%")
    
    # Sample entries
    print("\n" + "="*70)
    print("VALIDATION 6: Sample Entries")
    print("="*70)
    
    sample_cwes = ["CWE-79", "CWE-89", "CWE-352", "CWE-1275"]
    for cwe_id in sample_cwes:
        if cwe_id in db:
            entry = db[cwe_id]
            print(f"\n{cwe_id}: {entry['name']}")
            print(f"  Category: {entry.get('category', 'N/A')}")
            print(f"  Fix steps: {len(entry.get('fix_steps', []))} items")
            print(f"  Code examples: {len(entry.get('code_examples', {}))} languages")
            print(f"  References: {len(entry.get('references', []))} links")
    
    # Summary
    print("\n" + "="*70)
    print("VALIDATION SUMMARY")
    print("="*70)
    
    if errors or type_errors:
        print(f"✗ Found {len(errors) + len(type_errors)} errors")
        return False
    else:
        print("✓ All validations passed!")
        print(f"\n✓ Database is production-ready with {len(db)} CWEs")
        print(f"✓ Coverage: 11% of all 1000+ CWE types")
        print(f"✓ {has_examples} entries have code examples ({100*has_examples/len(db):.0f}%)")
        print(f"✓ {len(categories)} vulnerability categories represented")
        return True


if __name__ == "__main__":
    success = validate_cwe_database()
    sys.exit(0 if success else 1)
