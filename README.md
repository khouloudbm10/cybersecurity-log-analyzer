# Cybersecurity Log Analyzer

A beginner-friendly Python project that analyzes security log files, identifies repeated failed login attempts, and generates a readable security report.

## Overview

The Cybersecurity Log Analyzer is a small defensive security tool built with Python. It processes sample authentication logs, counts login events, and flags IP addresses with repeated failed login attempts for further investigation.

This project demonstrates fundamental skills in Python programming, log analysis, cybersecurity concepts, automated testing, and technical documentation.

## Features

- Parses log files line by line.
- Counts successful login events and failed login attempts.
- Identifies repeated failed login attempts using a configurable threshold.
- Tracks unauthorized access events by source IP address.
- Generates a timestamped text report.
- Handles common file-reading and report-writing errors.
- Includes automated unit tests using Python's built-in `unittest` framework.

## Technologies

- **Language:** Python
- **Libraries:** `pathlib`, `collections`, `datetime`, `unittest`
- **Tools:** Visual Studio Code, Git, GitHub

No third-party Python packages are required.

## Project Structure

```text
cybersecurity-log-analyzer/
├── main.py
├── sample.log
├── report.txt
├── test_analyzer.py
├── README.md
└── .gitignore
```

- `main.py` — analyzes logs and generates reports.
- `sample.log` — fictional security events for testing.
- `report.txt` — generated analysis report.
- `test_analyzer.py` — automated tests.
- `README.md` — project documentation.
- `.gitignore` — excludes unnecessary files from Git.

## Getting Started

### 1. Requirements

- Python 3.10 or newer
- Git (optional for running locally; required for Git-based version control)

### 2. Clone the repository

```bash
git clone https://github.com/khouloudbm10/cybersecurity-log-analyzer.git
cd cybersecurity-log-analyzer
```

Alternatively, download the project and open its folder in Visual Studio Code.

### 3. Run the analyzer

```bash
python main.py
```

On Windows, you can also use:

```powershell
py main.py
```

The program reads `sample.log`, displays a summary, and saves the generated report to `report.txt`.

### 4. Run the tests

```bash
python -m unittest -v
```

On Windows, if needed:

```powershell
py -m unittest -v
```

The tests cover sample-log counts, repeated failed-login detection, the threshold behavior, empty files, and report content.

## Detection Logic

The analyzer uses a configurable threshold of three failed login attempts per IP address.

For example, an IP address associated with three failed login events triggers an alert.

This rule identifies patterns worth investigating; it does not prove that an attack occurred. The current version does not correlate events across time windows or validate IP addresses.

## Example Results

Using the included sample data, the analyzer should report:

| Metric | Expected result |
|---|---:|
| Total log entries | 12 |
| Successful logins | 4 |
| Failed login attempts | 6 |
| Unauthorized access events | 2 |
| IP addresses triggering repeated-login alerts | 2 |

## Limitations and Future Improvements

This is an educational project and is not intended for production security monitoring.

Possible future improvements:

- Validate log formats and IP addresses.
- Detect failed login bursts within configurable time windows.
- Export reports to CSV or JSON.
- Add command-line options for custom log files and thresholds.
- Introduce severity levels and structured logging.
- Add more test cases for malformed entries and file errors.

## Security and Privacy

The included log entries are fictional and use IP address ranges reserved for documentation examples.

Only analyze logs you own or are authorized to access. Review logs for sensitive information before sharing them publicly.

## Learning Objectives

This project helped me practice:

- Python file handling and path management.
- Dictionaries and counters for event aggregation.
- Basic defensive security monitoring.
- Writing and running automated unit tests.
- Documenting a technical project for other developers.

---

**Author:** KHOULOUD BELMABROUK

**Status:** Educational project — initial version