#!/bin/bash

clear
echo "════════════════════════════════════════════════════════════"
echo "🐉 Kali GPT Advanced - Installation Script"
echo "════════════════════════════════════════════════════════════"
echo ""

# Check if running on Kali/Debian-based system
if ! command -v apt &> /dev/null; then
    echo "⚠️  Warning: This script is designed for Debian-based systems (Kali Linux)"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "[1/6] 📦 Updating system and installing dependencies..."
sudo apt update -qq
sudo apt install -y python3 python3-pip python3-venv xclip git curl -qq

echo "[2/6] 🐍 Creating Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

echo "[3/6] 📚 Installing Python dependencies..."
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo "✓ Dependencies installed"

echo "[4/6] 🔑 Setting up configuration files..."
# Create .env if it doesn't exist
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "✓ Created .env from .env.example - PLEASE ADD YOUR API KEY"
    else
        cat > .env << 'EOF'
# OpenAI API Configuration
OPENAI_API_KEY=your-api-key-here

# Get your API key from: https://platform.openai.com/api-keys
EOF
        echo "✓ Created .env file - PLEASE ADD YOUR API KEY"
    fi
    echo "  Edit .env and replace 'your-api-key-here' with your OpenAI API key"
else
    echo "✓ .env file already exists"
fi

# Make scripts executable
chmod +x kali-gpt.py kali-gpt-advanced.py

echo "[5/6] 📁 Creating config directory..."
mkdir -p ~/.kali-gpt
echo "✓ Config directory created at ~/.kali-gpt"

echo "[6/6] 🔗 Creating symbolic links (optional)..."
if [ -w "/usr/local/bin" ]; then
    sudo ln -sf "$(pwd)/kali-gpt-advanced.py" /usr/local/bin/kali-gpt 2>/dev/null && \
        echo "✓ Created symlink: kali-gpt command available globally" || \
        echo "  (Skipped global command - run locally instead)"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "✅ Installation Complete!"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "📝 Next Steps:"
echo "  1. Edit .env and add your OpenAI API key"
echo "  2. Get API key from: https://platform.openai.com/api-keys"
echo ""
echo "🚀 To start Kali GPT Advanced:"
echo "  source venv/bin/activate"
echo "  ./kali-gpt-advanced.py"
echo ""
echo "📘 Or use the basic version:"
echo "  source venv/bin/activate"
echo "  ./kali-gpt.py"
echo ""
echo "════════════════════════════════════════════════════════════"
