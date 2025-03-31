import os
import re
import sqlite3
import zipfile
import zstandard as zstd
import argparse
from typing import Optional


def extract_apkg(apkg_file: str, extract_folder: str) -> None:
    """Extracts the .apkg file into a folder."""
    os.makedirs(extract_folder, exist_ok=True)
    try:
        with zipfile.ZipFile(apkg_file, 'r') as zip_ref:
            zip_ref.extractall(extract_folder)
        print(f"Extracted {apkg_file} to {extract_folder}")
    except zipfile.BadZipFile:
        print(f"[!] Error: The file {apkg_file} is not a valid zip archive.")
    except Exception as e:
        print(f"[!] Error: Failed to extract {apkg_file}. {e}")


def decompress_anki21b(input_file: str, output_file: str) -> None:
    """Decompresses collection.anki21b (Zstandard) to collection.anki2."""
    try:
        with open(input_file, 'rb') as compressed, open(output_file, 'wb') as decompressed:
            dctx = zstd.ZstdDecompressor()
            decompressed.write(dctx.stream_reader(compressed).read())
        print(f"Decompressed {input_file} to {output_file}")
    except FileNotFoundError:
        print(f"[!] Error: {input_file} not found.")
    except Exception as e:
        print(f"[!] Error: Failed to decompress {input_file}. {e}")


def scan_for_patterns_in_column(column: str, preview_length: int) -> None:
    """Scans a column for suspicious patterns and prints warnings."""
    patterns = [
        (r'<script>|onload=|eval\(|exec\(', "Potentially malicious JavaScript"),
        (r'os\.system|subprocess\.run|eval\(|exec\(', "Suspicious Python execution"),
        (r'<iframe|<object|<embed|onclick=', "Suspicious iframe/object/embed"),
        (r'`[^`]+`|\$\(.*\)', "Potential shell command execution")
    ]
    
    for pattern, warning in patterns:
        if re.search(pattern, column, re.IGNORECASE):
            if len(column) > preview_length:
                print(f"[!] {warning} detected: {column[:preview_length]}...")
                user_input = input("Expand warning to full text? (y/n): ").strip().lower()
                if user_input == 'y':
                    print(f"[!] Full content:\n{column}\n")
            else:
                print(f"[!] {warning} detected: {column}")


def scan_table(cursor, table_name: str, preview_length: int) -> None:
    """Scans a specific table for suspicious content."""
    print(f"Scanning table: {table_name}")
    cursor.execute(f"SELECT * FROM {table_name} LIMIT 50")  # Limit to 50 rows per table to avoid huge results
    rows = cursor.fetchall()
    for row in rows:
        for column in row:
            if isinstance(column, str):  # Only scan string fields for patterns
                scan_for_patterns_in_column(column, preview_length)


def scan_triggers(cursor) -> None:
    """Scans triggers for suspicious SQL statements."""
    cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='trigger'")
    triggers = cursor.fetchall()
    for name, sql in triggers:
        if re.search(r'delete|drop|alter|attach|pragma', sql, re.IGNORECASE):
            print(f"[!] Suspicious trigger detected: {name}\n{sql}\n")


def scan_notes(cursor, preview_length: int) -> None:
    """Scans the notes table for suspicious content."""
    cursor.execute("SELECT flds FROM notes LIMIT 50")
    notes = cursor.fetchall()
    for note in notes:
        text = note[0]
        scan_for_patterns_in_column(text, preview_length)


def scan_sqlite(db_path: str, preview_length: int = 300, scan_all: bool = False) -> None:
    """Scans the SQLite database for anomalies, optionally scanning all tables."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        if scan_all:
            # Scan all tables for suspicious content
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            for table in tables:
                scan_table(cursor, table[0], preview_length)
        else:
            # Scan only the predefined tables (sqlite_master and notes)
            scan_triggers(cursor)
            scan_notes(cursor, preview_length)

        conn.close()
    except sqlite3.DatabaseError as e:
        print(f"[!] Error: Failed to scan the SQLite database at {db_path}. {e}")
    except Exception as e:
        print(f"[!] Error: An unexpected error occurred while scanning the database. {e}")


def main(apkg_file: str, preview_length: int = 300, scan_all: bool = False) -> None:
    """Main function to process the .apkg file."""
    extract_folder = "extracted_apkg"
    extract_apkg(apkg_file, extract_folder)

    db_path = os.path.join(extract_folder, "collection.anki2")
    compressed_db_path = os.path.join(extract_folder, "collection.anki21b")

    if os.path.exists(compressed_db_path):
        decompress_anki21b(compressed_db_path, db_path)

    if os.path.exists(db_path):
        scan_sqlite(db_path, preview_length, scan_all)
    else:
        print("[!] No valid SQLite database found.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan .apkg files for anomalies.")
    parser.add_argument("apkg_file", help="Path to the .apkg file to scan")
    parser.add_argument("-p", "--preview-length", type=int, default=300, 
                        help="Set the preview length for the notes content (default: 300)")
    parser.add_argument("-a", "--all-tables", action="store_true", 
                        help="Scan all tables in the database (default: only scan limited tables)")

    args = parser.parse_args()

    # Run the main function with the parsed arguments
    main(args.apkg_file, args.preview_length, args.all_tables)
