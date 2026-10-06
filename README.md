# Security Log Analyzer

A simple desktop security log analysis tool created with Python. This project is designed as a beginner / first-year cybersecurity portfolio project.

The application reads log files, extracts useful security information, and highlights suspicious activity using simple rule-based detection.

## Features

- Upload `.log` and `.txt` files
- Analyze Linux authentication logs
- Analyze basic Apache access logs
- Extract IP addresses using regular expressions
- Identify failed and successful login attempts
- Detect possible brute-force attacks
- Detect successful login after repeated failures
- Detect simple unauthorized access attempts
- Search analyzed results
- Filter by severity
- Filter by date
- Show basic dashboard statistics
- Display two simple Matplotlib charts
- Export analysis results to CSV
- Show clear error messages for unsupported files

## Brute-Force Rule

For this student project, a possible brute-force attack is detected when the same IP address has at least **5 failed login attempts within 5 minutes**.

This is a simple rule created for learning purposes. Real SOC and SIEM systems normally use more advanced detection rules and additional context.

## Technologies Used

- Python 3
- Tkinter
- Regular Expressions (`re`)
- Matplotlib
- Python `csv`
- Python `collections`

Tkinter is included with most normal Python installations, so the only external library used by this project is Matplotlib.

## Project Structure

```text
Security-Log-Analyzer/
|
|-- security_log_analyzer.py
|-- sample_logs/
|   |-- auth.log
|   `-- apache_access.log
|-- screenshots/
|-- README.md
|-- requirements.txt
`-- LICENSE
```

## Installation

### 1. Clone or download the project

Open a terminal inside the project folder.

### 2. Optional: create a virtual environment

```bash
python -m venv .venv
```

On Windows:

```bash
.venv\Scripts\activate
```

On macOS or Linux:

```bash
source .venv/bin/activate
```

### 3. Install the requirement

```bash
python -m pip install -r requirements.txt
```

### 4. Run the program

```bash
python security_log_analyzer.py
```

## How to Use

1. Start the program.
2. Click **Upload Log File**.
3. Select a `.log` or `.txt` file.
4. Click **Analyze Logs**.
5. View the dashboard statistics and results table.
6. Use the search, severity, and date filters if needed.
7. Click **Show Charts** to view simple security charts.
8. Click **Export CSV** to save the analysis results.

You can test the application using the files inside the `sample_logs` folder.

## Dashboard Information

The dashboard shows:

- Total log entries
- Failed login attempts
- Successful logins
- Unique IP addresses
- Suspicious IP addresses
- Security alerts

## Severity Levels

The application uses four simple severity levels:

- **LOW** - normal or informational activity
- **MEDIUM** - failed authentication attempts
- **HIGH** - suspicious or unauthorized activity
- **CRITICAL** - possible brute-force attack

## Cybersecurity Concepts Demonstrated

This project demonstrates beginner knowledge of:

- Log analysis
- Authentication monitoring
- IP address extraction
- Brute-force attack detection
- Unauthorized access monitoring
- Basic SOC investigation
- Rule-based security detection
- Security event severity

## Limitations

This is an educational project and not a replacement for a professional SIEM system. The rules are intentionally simple and some unusual log formats may not be recognized.

## Repository Notes

- Sample logs are included for testing only.
- Generated CSV exports, virtual environments, and Python cache files are ignored by Git.
- Screenshots can be added to the `screenshots` folder for a richer GitHub project page.

## Future Improvements

Possible future improvements include:

- More log formats
- More charts
- Better date/time filtering
- Port scan detection
- Database storage
- PDF report generation

## License

This project is released under the MIT License.
