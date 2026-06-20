#!/bin/bash
# Instalador do BugBounty Scanner

echo "[*] Criando ambiente virtual..."
python3 -m venv venv
source venv/bin/activate

echo "[*] Instalando dependências Python..."
pip install --upgrade pip
pip install requests beautifulsoup4 dnspython selenium webdriver-manager python-nmap sslyze markdown jinja2 tqdm colorama python-dotenv aiohttp

echo "[*] Criando wrapper global opium..."
sudo tee /usr/local/bin/opium > /dev/null << 'EOF'
#!/bin/bash
cd /home/$USER/bugbounty-scanner
source venv/bin/activate
python scan_bugbounty.py "$@"
EOF

sudo chmod +x /usr/local/bin/opium

echo "[✓] Instalação concluída! Execute 'opium' para iniciar."
