#!/usr/bin/env python3
"""
Generate llms-full.txt by concatenating README.md and all docs files.
This file is useful for LLM context when working on the project.
"""

import os
from pathlib import Path
import re


def natural_sort_key(s):
    """Sort strings with numbers naturally (e.g., 01, 02, 10, 11)."""
    return [int(text) if text.isdigit() else text.lower()
            for text in re.split('([0-9]+)', str(s))]


def main():
    # Get project root directory
    root_dir = Path(__file__).parent

    # Output file
    output_file = root_dir / "llms-full.txt"

    # README file
    readme_file = root_dir / "README.md"

    # Docs directory
    docs_dir = root_dir / "docs"

    # Collect all markdown files in docs/
    doc_files = []
    if docs_dir.exists():
        doc_files = sorted(docs_dir.glob("*.md"), key=natural_sort_key)

    # Write to output file
    with open(output_file, 'w', encoding='utf-8') as outfile:
        # Write header
        outfile.write("=" * 80 + "\n")
        outfile.write("AuthGlow - Complete Documentation for LLMs\n")
        outfile.write("=" * 80 + "\n\n")

        # Write README
        if readme_file.exists():
            outfile.write("=" * 80 + "\n")
            outfile.write("README.md\n")
            outfile.write("=" * 80 + "\n\n")

            with open(readme_file, 'r', encoding='utf-8') as infile:
                outfile.write(infile.read())

            outfile.write("\n\n")

        # Write each doc file
        for doc_file in doc_files:
            outfile.write("=" * 80 + "\n")
            outfile.write(f"docs/{doc_file.name}\n")
            outfile.write("=" * 80 + "\n\n")

            with open(doc_file, 'r', encoding='utf-8') as infile:
                outfile.write(infile.read())

            outfile.write("\n\n")

    print(f"Generated {output_file}")
    print(f"Included files:")
    print(f"   - README.md")
    for doc_file in doc_files:
        print(f"   - docs/{doc_file.name}")
    print(f"\nTotal size: {output_file.stat().st_size:,} bytes")


if __name__ == "__main__":
    main()
