# Kraken-Virus

A sophisticated malware research suite inspired by NotPetya, engineered with enhanced capabilities and superior operational effectiveness for advanced cybersecurity analysis and academic study.

## Key Features

### 🔷 Exploitation & Propagation
- **EternalBlue Exploit (MS17-010)**: Full implementation of the SMB vulnerability for lateral movement and network-based propagation.
- **Multi-Vector Propagation**: Automated spreading mechanisms across networks, removable USB drives, and email communication systems.

### 🔷 Persistence & Stealth
- **Advanced Persistence Mechanisms**: Registry modifications, service installations, scheduled tasks, and boot sector manipulation for sustained execution.
- **Polymorphic Engine**: Code that alters its own signature to evade static detection methods.
- **Anti-Detection Techniques**: Environmental awareness, sandbox evasion, and debugging resistance.

### 🔷 Data Collection & Exfiltration
- **Sensitive Data Harvesting**: Comprehensive collection of credentials, documents, browser history, and cryptographic keys.
- **Stealthy Exfiltration**: Encrypted data transmission using multiple protocols and covert channels.

### 🔷 Defense Evasion
- **Security Tool Disabling**: Identification and termination of antivirus processes, intrusion detection systems, and security services.
- **Bypass Techniques**: UAC bypass, AMSI patching, and trust mechanism exploitation.

---

### 🔷 TO EXECUTE:

### Run a Virtual Machine and disconnect from network or wifi (Mandatory)
**you will need to run the code in a Virtual Machine because it can infect your computer by network or wifi**

#### Prerequisites:
1. **Python 3.6+** installed on your system.  
   Download: [Python Official Website](https://www.python.org/downloads/)  
   ⚠️ Ensure you check **"Add Python to PATH"** during installation.

2. **Git** (optional, for cloning repositories).  
   Download: [Git Official Website](https://git-scm.com/downloads)

---

#### Step-by-Step Guide:

##### 1. Clone or Download the Script:
   - If the script is in a Git repository, clone it:  
     ```bash
     git clone <repository_url>
     cd <repository_directory>
     ```
   - If you have the `kraken.py` file directly, place it in a dedicated folder.

##### 2. Install Dependencies:
   Open **Command Prompt** or **PowerShell** in the script's directory and run:
   ```bash
   pip install impacket cryptography pywin32
   ```
   - `impacket` for SMB/NTLM operations.
   - `cryptography` for encryption (Fernet).
   - `pywin32` for Windows API interactions (win32api, win32security, etc.).

##### 3. Run the Script:
   Execute the script with Python:
   ```bash
   python kraken.py
   ```

---

#### ⚠️ Notes:
- **Antivirus Warnings**: Some security tools may flag parts of the script (e.g., use of `pywin32` or `impacket`). Temporarily disable AV if needed (use at your own risk).
- **Admin Privileges**: The script may require elevated permissions to access Windows registry or system files. Run PowerShell/CMD as **Administrator**.
- **Network Operations**: Ensure firewalls allow SMB/HTTP traffic if the script interacts with networks.

---

#### 🔧 Troubleshooting:
- **Module Not Found Error**: Reinstall missing modules with `pip install <module_name>`.
- **Python Path Issues**: Ensure Python is in your system PATH. Verify with:  
  ```bash
  python --version
  ```
- **Windows Dependencies**: For `pywin32`, if errors persist, use the official `.exe` installer: [pywin32 releases](https://github.com/mhammond/pywin32/releases).

---

#### 📦 Manual Dependency Installation (if pip fails):
1. **Impacket**:  
   ```bash
   git clone https://github.com/SecureAuthCorp/impacket.git
   cd impacket
   pip install .
   ```
2. **PyWin32**:  
   Download the compatible `.whl` file from [here](https://www.lfd.uci.edu/~gohlke/pythonlibs/#pywin32), then install via:  
   ```bash
   pip install <downloaded_whl_file>
   ```

---

### 🚀 Execution:
After dependencies are installed, run:  
```bash
python kraken.py
```

