# Process Masquerade Detector

A Python-based GUI forensic tool designed to detect malware hiding as system processes. It features a powerful scanning engine that validates running processes against authorized system paths to find "masquerading" threats—all within a single, user-friendly interface.

## Features

- **Deep Scan Validation**: Automatically compares running processes against a strict "Known-Good" whitelist of system paths.
- **Real-Time Detection**: Instantly flags processes running from volatile directories like `Downloads`, `AppData`, or `Temp`.
- **Kill Switch**: Allows administrators to terminate confirmed masquerading processes immediately.
- **Safety Filters**: Automatically ignores verified system processes to prevent accidental system instability.

## Built with

- **Python** 
- **Tkinter** (GUI)
- **psutil**
- **Windows API**

## Requirements

Before running the tool, ensure you have the following dependencies installed:

```bash
pip install psutil
```
Windows Only: This tool requires Administrator privileges to function correctly.

# Running the Tool

- Open a terminal or command prompt with Administrator privileges.

- Navigate to the directory where detecter.py is located.

Run the script:
```bash
python detector.py
```
## Usage Guide
**1. Run as Admin**

Launch the script with Administrator rights to ensure it has permission to access system details.

**2. Deep Scan**

Click the "Deep Scan" button on the dashboard to begin scanning for masquerading processes.

**3. Review Results**

Safe Processes: Verified system processes are filtered out.

Rogue Processes: Suspicious processes (e.g., svchost.exe running from Temp) are highlighted in RED for easy identification.

**4. Neutralize**

Select the suspicious process from the list.

Click "Neutralize Threat" to terminate the process.

**5. Manual Confirmation**

- Before terminating any process, the tool will prompt a confirmation popup:

   **"Are you sure you want to terminate this process?"**

- This ensures that the user gives explicit consent before any system action is taken.

 **6. Whitelist Safety Protection**

The program contains a hardcoded whitelist of critical Windows paths (e.g., System32) to prevent accidental system instability.It automatically ignores verified system files to ensure they are not flagged as rogue processes.

## Ethical Rules in the Program

- Manual Confirmation Prompt: Processes are not automatically terminated. A manual confirmation step ensures user consent before any action.

- Whitelist Safety Protection: Critical Windows directories are whitelisted to avoid disrupting the system.

- Visible GUI Execution: The tool runs with a visible GUI dashboard that makes its function and findings clear at all times.

## Ethical Notice

This tool is for educational and ethical defense purposes only. It is designed to help administrators secure their own systems. The developer is not responsible for any data loss or system instability caused by the incorrect termination of processes.
