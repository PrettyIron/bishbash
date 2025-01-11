# Bash History Extraction from Running Processes

## Overview

This project demonstrates how to extract **Bash history** from running processes using memory inspection techniques. It includes:

1. **`find_history_ptrace.c`**: A C program utilizing `ptrace` for memory inspection and history extraction.  
2. **`find_history.py`**: A Python script reading process memory via `/proc/[pid]/mem`.

These tools were created as part of an article in the **DigitalWhisper** magazine.

---

## Usage

### C Implementation
```bash
sudo ./find_history_ptrace <bash_pid>
```

### Python Implementation
```bash
sudo python3 find_history.py <bash_pid>
```

---

## Notes

- Designed for educational purposes only. Unauthorized use is prohibited.
- Offsets and addresses may require adjustments based on the Bash version.