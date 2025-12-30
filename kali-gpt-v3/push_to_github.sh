#!/bin/bash
#
# Push Kali-GPT v3 to GitHub
# Choose your method below
#

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "═══════════════════════════════════════════════════════════"
echo "          PUSH KALI-GPT V3 TO GITHUB"
echo "═══════════════════════════════════════════════════════════"
echo -e "${NC}"

# Get GitHub repo URL
read -p "Enter your GitHub repo URL (e.g., https://github.com/username/kali-gpt): " REPO_URL

if [ -z "$REPO_URL" ]; then
    echo -e "${RED}Error: No repo URL provided${NC}"
    exit 1
fi

echo ""
echo "Choose push method:"
echo "  1) Create new 'v3' branch (keeps original code)"
echo "  2) Replace main branch completely"
echo "  3) Add v3 as subfolder in existing repo"
echo ""
read -p "Select option [1-3]: " METHOD

case $METHOD in
    1)
        echo -e "${CYAN}[*] Creating v3 branch...${NC}"
        
        # Initialize git if needed
        git init 2>/dev/null
        
        # Add remote
        git remote remove origin 2>/dev/null
        git remote add origin "$REPO_URL"
        
        # Create and switch to v3 branch
        git checkout -b v3
        
        # Add all files
        git add -A
        git commit -m "Kali-GPT v3: Autonomous AI Penetration Testing

Features:
- Autonomous ReAct Agent
- Local LLM Support (Ollama)
- MITRE ATT&CK Integration
- Intelligent Tool Chaining
- Persistent Memory System
- Safe Command Execution"

        # Push to v3 branch
        git push -u origin v3
        
        echo -e "${GREEN}[+] Pushed to branch 'v3'${NC}"
        echo -e "${YELLOW}To merge into main later: git checkout main && git merge v3${NC}"
        ;;
        
    2)
        echo -e "${YELLOW}[!] Warning: This will replace your main branch${NC}"
        read -p "Are you sure? (yes/no): " CONFIRM
        
        if [ "$CONFIRM" != "yes" ]; then
            echo "Cancelled"
            exit 0
        fi
        
        git init 2>/dev/null
        git remote remove origin 2>/dev/null
        git remote add origin "$REPO_URL"
        
        git add -A
        git commit -m "Kali-GPT v3: Complete Rewrite - Autonomous AI Pentester"
        
        git branch -M main
        git push -f origin main
        
        echo -e "${GREEN}[+] Pushed to main branch${NC}"
        ;;
        
    3)
        echo -e "${CYAN}[*] This will clone your repo and add v3 as subfolder${NC}"
        
        TEMP_DIR="/tmp/kali-gpt-merge-$$"
        mkdir -p "$TEMP_DIR"
        
        # Clone existing repo
        git clone "$REPO_URL" "$TEMP_DIR/repo"
        
        # Copy v3 into subfolder
        mkdir -p "$TEMP_DIR/repo/v3"
        cp -r ./* "$TEMP_DIR/repo/v3/" 2>/dev/null
        rm -f "$TEMP_DIR/repo/v3/push_to_github.sh"
        
        cd "$TEMP_DIR/repo"
        
        git add -A
        git commit -m "Add Kali-GPT v3 autonomous version"
        git push origin main
        
        echo -e "${GREEN}[+] Added v3 as subfolder${NC}"
        echo -e "${CYAN}Your repo now has:${NC}"
        echo "  /           - Original kali-gpt"
        echo "  /v3/        - New autonomous version"
        
        # Cleanup
        rm -rf "$TEMP_DIR"
        ;;
        
    *)
        echo -e "${RED}Invalid option${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}                    DONE!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
