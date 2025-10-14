#!/usr/bin/env python3
# Path: /home/dijital/Documents/auditkit-all/auditkit/scanner/fix_pdf.py
# Run: python3 fix_pdf.py

import sys

pdf_file = "pkg/report/pdf.go"

print(f"Reading {pdf_file}...")

try:
    with open(pdf_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    print(f"Total lines: {len(lines)}")
    print(f"\nShowing lines 740-750 BEFORE fix:")
    for i in range(739, min(750, len(lines))):
        print(f"Line {i+1}: {repr(lines[i])}")
    
    # Fix lines 745-747 (0-indexed: 744-746)
    if len(lines) > 746:
        # Replace line 746 (index 745)
        lines[745] = '\t\t\t"Note: This is FREE version with about 150 controls.",\n'
        # Replace line 747 (index 746)
        lines[746] = '\t\t\t"For complete 1000 plus control coverage integrate with Prowler:",\n'
        
        print(f"\nShowing lines 740-750 AFTER fix:")
        for i in range(739, min(750, len(lines))):
            print(f"Line {i+1}: {repr(lines[i])}")
        
        # Write back
        with open(pdf_file, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        
        print(f"\n✅ Fixed! Now run: go build ./cmd/auditkit")
    else:
        print(f"❌ File has fewer lines than expected: {len(lines)}")
        
except FileNotFoundError:
    print(f"❌ File not found: {pdf_file}")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error: {e}")
    sys.exit(1)
