#!/bin/bash
#
# Kali-GPT v3 Setup Script
# Autonomous AI-Powered Penetration Testing Assistant
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    KALI-GPT v3 SETUP                          ║"
echo "║         Autonomous AI Penetration Testing Assistant           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo -e "${YELLOW}Warning: This tool is designed for Kali Linux/Debian${NC}"
fi

# Check Python version
echo -e "${CYAN}[*] Checking Python version...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    echo -e "${GREEN}[+] Python $PYTHON_VERSION found${NC}"
    
    # Check if version is >= 3.10
    if python3 -c 'import sys; exit(0 if sys.version_info >= (3, 10) else 1)'; then
        echo -e "${GREEN}[+] Python version is compatible${NC}"
    else
        echo -e "${RED}[!] Python 3.10+ required. Please upgrade Python.${NC}"
        exit 1
    fi
else
    echo -e "${RED}[!] Python3 not found. Please install Python 3.10+${NC}"
    exit 1
fi

# Create virtual environment
echo -e "${CYAN}[*] Creating virtual environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}[+] Virtual environment created${NC}"
else
    echo -e "${YELLOW}[*] Virtual environment already exists${NC}"
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo -e "${CYAN}[*] Upgrading pip...${NC}"
pip install --upgrade pip > /dev/null 2>&1

# Install requirements
echo -e "${CYAN}[*] Installing Python dependencies...${NC}"
pip install -r requirements.txt > /dev/null 2>&1
echo -e "${GREEN}[+] Dependencies installed${NC}"

# Check for Ollama
echo -e "${CYAN}[*] Checking for Ollama (local LLM)...${NC}"
if command -v ollama &> /dev/null; then
    echo -e "${GREEN}[+] Ollama found${NC}"
    
    # Check if Ollama is running
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo -e "${GREEN}[+] Ollama server is running${NC}"
        
        # Check for llama3.2 model
        if ollama list | grep -q "llama3.2"; then
            echo -e "${GREEN}[+] llama3.2 model available${NC}"
        else
            echo -e "${YELLOW}[*] llama3.2 model not found. Installing...${NC}"
            echo -e "${YELLOW}    This may take a few minutes for the first download${NC}"
            ollama pull llama3.2
            echo -e "${GREEN}[+] llama3.2 model installed${NC}"
        fi
    else
        echo -e "${YELLOW}[!] Ollama server not running. Start with: ollama serve${NC}"
    fi
else
    echo -e "${YELLOW}[!] Ollama not found${NC}"
    echo ""
    echo -e "${CYAN}To use free local AI, install Ollama:${NC}"
    echo -e "  curl -fsSL https://ollama.com/install.sh | sh"
    echo -e "  ollama pull llama3.2"
    echo -e "  ollama serve"
    echo ""
    echo -e "${CYAN}Or set OPENAI_API_KEY for cloud AI:${NC}"
    echo -e "  export OPENAI_API_KEY=your-key-here"
fi

# Create config directory
CONFIG_DIR="$HOME/.kali-gpt-v3"
echo -e "${CYAN}[*] Creating config directory...${NC}"
mkdir -p "$CONFIG_DIR"
echo -e "${GREEN}[+] Config directory: $CONFIG_DIR${NC}"

# Create .env file if not exists
if [ ! -f ".env" ]; then
    echo -e "${CYAN}[*] Creating .env file...${NC}"
    cat > .env << 'EOF'
# Kali-GPT v3 Configuration

# LLM Provider: ollama (default) or openai
LLM_PROVIDER=ollama

# Ollama settings (for local AI)
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.2

# OpenAI settings (optional, for cloud AI)
# OPENAI_API_KEY=your-key-here
# OPENAI_MODEL=gpt-4o-mini

# Agent settings
MAX_ITERATIONS=100
REQUIRE_CONFIRMATION=true
DEFAULT_TIMEOUT=300
EOF
    echo -e "${GREEN}[+] .env file created${NC}"
else
    echo -e "${YELLOW}[*] .env file already exists${NC}"
fi

# Make main.py executable
chmod +x main.py

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    SETUP COMPLETE!                            ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}To start Kali-GPT v3:${NC}"
echo ""
echo -e "  ${YELLOW}source venv/bin/activate${NC}"
echo -e "  ${YELLOW}python main.py${NC}"
echo ""
echo -e "${CYAN}Quick start:${NC}"
echo -e "  ${YELLOW}./start.sh${NC}"
echo ""

# Create start script
cat > start.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
python main.py
EOF
chmod +x start.sh

echo -e "${GREEN}Happy Hacking! 🐉${NC}"
