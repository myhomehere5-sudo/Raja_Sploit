#!/usr/bin/env bash
# setup.sh - Rajasploit setup helper
# Usage: ./setup.sh
# This script will:
#  - create a python venv (raja_venv)
#  - install python requirements into the venv
#  - create standard directories (results graphs reports logs modules reconnaissance resources)
#  - optionally install recommended system packages (Kali/Debian/Ubuntu based)
#  - give instructions for wkhtmltopdf and Gmail app password

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${PROJECT_DIR}/raja_venv"

echo
echo "Rajasploit setup"
echo "Project directory: ${PROJECT_DIR}"
echo

# 1) Ensure python3 exists
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is not installed. Please install Python 3 and re-run this script."
  exit 1
fi

# 2) Create virtual environment
if [ -d "${VENV_DIR}" ]; then
  echo "Virtualenv already exists: ${VENV_DIR}"
else
  echo "Creating python venv at: ${VENV_DIR}"
  python3 -m venv "${VENV_DIR}"
fi

# 3) Activate and upgrade pip, install requirements
echo
echo "Activating venv and installing Python packages..."
# shellcheck disable=SC1090
source "${VENV_DIR}/bin/activate"

python -m pip install --upgrade pip setuptools wheel
if [ -f "${PROJECT_DIR}/requirements.txt" ]; then
  pip install -r "${PROJECT_DIR}/requirements.txt"
else
  echo "requirements.txt not found. Installing core packages as fallback..."
  pip install colorama requests matplotlib jinja2 pdfkit reportlab
fi

# 4) Create directory structure
echo
echo "Creating directory structure..."
mkdir -p "${PROJECT_DIR}/modules"
mkdir -p "${PROJECT_DIR}/reconnaissance"
mkdir -p "${PROJECT_DIR}/results"
mkdir -p "${PROJECT_DIR}/graphs"
mkdir -p "${PROJECT_DIR}/reports"
mkdir -p "${PROJECT_DIR}/logs"
mkdir -p "${PROJECT_DIR}/resources"

echo "Directories created (if missing): modules reconnaissance results graphs reports logs resources"

# 5) Offer to install recommended system packages (DEBIAN-based)
read -r -p "Do you want to install recommended system packages (nmap, nikto, sqlmap, hydra, john, aircrack-ng, metasploit-framework, tcpdump, yara, clamscan)? [y/N] " install_sys
install_sys=${install_sys:-N}

if [[ "$install_sys" =~ ^[Yy]$ ]]; then
  echo "Installing recommended packages via apt (requires sudo)..."
  echo "If you are on Kali this is fine; on other distros adjust package names as necessary."
  sudo apt update
  sudo apt install -y nmap nikto sqlmap hydra john aircrack-ng metasploit-framework tcpdump tshark suricata yara clamav net-tools
  echo "System packages installation finished."
else
  echo "Skipping system package installation. You can install later with apt."
fi

# 6) wkhtmltopdf note
echo
echo "NOTE: wkhtmltopdf is optional and used by pdfkit to convert HTML reports to PDF."
echo "Many modern distros don't have wkhtmltopdf in apt. If you need PDF generation via pdfkit,"
echo "download/install wkhtmltopdf from the official releases:"
echo "  https://github.com/wkhtmltopdf/wkhtmltopdf/releases"
echo "Alternatively the project uses reportlab as a fallback (already included)."

# 7) Final message
echo
echo "Setup complete. To start using Rajasploit:"
echo "  cd ${PROJECT_DIR}"
echo "  source ${VENV_DIR}/bin/activate"
echo "  python3 Rajasploit.py"
echo
echo "If you want the venv auto-activated, use 'source ${VENV_DIR}/bin/activate' each session."
echo
echo "For honeypot Gmail alerts: generate a Gmail App Password (Google account -> Security -> App passwords)."
echo "Then edit modules/honeypot.py and set GMAIL_USER & GMAIL_APP_PASSWORD variables (or use env vars)."
echo
echo "Happy testing — remember to use Rajasploit only on systems you are authorized to test."
