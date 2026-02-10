# File Hashing and Integrity Verification System
This project is a Python program that generates and verifies file hashes to check file integrity. It uses SHA-256 hashing and stores hash values in JSON files. Each file has its own hash table.
The program can detect if a file has been modified, deleted, or newly added.

## Features
- Uses SHA-256 cryptographic hashing
- Generates one JSON file per file
- Traverses directories recursively
- Verifies file integrity
- Detects file changes
- Command line interface
- Uses only built-in Python libraries

## Requirements
- Python 3
- Ubuntu/Linux (recommended)
