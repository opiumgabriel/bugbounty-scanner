# bugbounty-scanner
DEUS VULT - Ferramenta modular de Bug Bounty e Pentest (em desenvolvimento) com interface interativa, integração com +20 ferramentas e relatórios automáticos.
# ⚠️ FERRAMENTA EM FASE DE TESTES

**Este projeto está em desenvolvimento ativo. Podem existir bugs, funcionalidades incompletas e instabilidades. Use por sua conta e risco e reporte problemas abrindo uma issue.**

---

# 🛡️ DEUS VULT - BugBounty Scanner
███████████
███████████
███████████
███████████
██████████████████████████
██████████████████████████
██████████████████████████
███████████
███████████
███████████
███████████
██████████████████████████
██████████████████████████
██████████████████████████
███████████
███████████
███████████
███████████

text

**Versão 2.0 (Alpha) | By OpiumGabriel**

---

## ⚔️ Sobre a ferramenta

O **DEUS VULT - BugBounty Scanner** é um framework modular de pentest e bug bounty desenvolvido para automatizar o reconhecimento, varredura de vulnerabilidades e exploração em alvos autorizados. Ele reúne as principais ferramentas de segurança ofensiva em uma interface interativa e fácil de usar.

**⚠️ Aviso importante:**
- Esta ferramenta está em **fase de testes**.
- Podem existir bugs, falhas e comportamentos inesperados.
- **Use apenas em ambientes que você possui autorização para testar.**
- O autor não se responsabiliza por mau uso ou danos causados.

---

## 🚀 Características principais

- ✅ Menu interativo com opções para Bug Bounty, Pentest, OSINT, Web Scanner e mais.
- ✅ Integração com +20 ferramentas (subfinder, httpx, nuclei, nmap, ffuf, sqlmap, etc.).
- ✅ Instalação automática de dependências e ferramentas.
- ✅ Relatórios automáticos em HTML/Markdown.
- ✅ Suporte a proxy e TOR para anonimato.
- ✅ Compatível com Kali Linux, Windows e macOS.

---

## 📦 Pré-requisitos

- **Git** (para clonar)
- **Python 3.8+** com pip
- **Go** (para ferramentas em Go)
- Conexão com a internet (para baixar ferramentas)

---

## 🔧 Instalação

### 🐧 Kali Linux / Linux (recomendado)

```bash
# 1. Clone o repositório
git clone https://github.com/opiumgabriel/bugbounty-scanner.git
cd bugbounty-scanner

# 2. Execute o instalador
chmod +x install.sh
./install.sh

# 3. Execute a ferramenta
opium
🪟 Windows
bash
git clone https://github.com/opiumgabriel/bugbounty-scanner.git
cd bugbounty-scanner
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python scan_bugbounty.py
🎮 Como usar
Execute opium (Linux) ou python scan_bugbounty.py (Windows).

O menu principal aparecerá com as opções:

text
0. Instalar/Atualizar ferramentas globalmente
1. Bug Bounty (modo automático)
2. Pentest Completo
3. OSINT
4. Web Scanner
5. Mobile
6. Wireless
7. Ferramentas Úteis
8. Configurações
9. Relatórios
10. Sincronizar com GitHub (push)
11. Sair
Exemplo de uso:

Escolha 1 → Bug Bounty.

Informe o alvo (ex: sankay.com.br).

O scanner executará as ferramentas em sequência.

Ao final, um relatório será salvo em reports/.

Comando direto (sem menu):

bash
opium --target sankay.com.br --mode bugbounty --limit 5 --no-screenshots
📂 Estrutura do projeto
text
bugbounty-scanner/
├── scan_bugbounty.py    # Script principal
├── install.sh           # Instalador automático
├── .env.example         # Exemplo de variáveis de ambiente
├── .gitignore           # Arquivos ignorados pelo Git
├── reports/             # Relatórios gerados
└── logs/                # Logs de execução
🧠 Dicas importantes
Use --no-screenshots para evitar dependência do Selenium.

Configure proxy/TOR no menu de configurações (opção 8).

Sempre atualize o repositório antes de usar:

bash
git pull origin main
📜 Licença
MIT License – veja o arquivo LICENSE para mais detalhes.

🙏 Agradecimentos
Nous Research (Hermes Agent) – inspiração para o design.

ProjectDiscovery (subfinder, nuclei, httpx).

Tomnomnom (assetfinder, waybackurls).

Comunidade de bug bounty e segurança ofensiva.

⚠️ Aviso legal
Esta ferramenta é fornecida apenas para fins educacionais e de testes de segurança autorizados. O uso indevido para acessar sistemas sem permissão é ilegal e viola os Termos de Serviço de terceiros. O autor não se responsabiliza por qualquer dano ou violação causada pelo uso da ferramenta.

Lembre-se: Com grandes poderes vêm grandes responsabilidades. Use com sabedoria. 🛡️

DEUS VULT! ⚔️
