# Haven - Next-Gen Network Scanner & Forensics Suite

**Haven** é uma suíte avançada de varredura, análise e forense de redes desenvolvida por SyraDevOps & TLS. Projetada para profissionais de segurança, administradores de redes e entusiastas, Haven reúne em um só lugar recursos de scanner, sniffer, fingerprinting, análise de anomalias, geração de relatórios e muito mais.

---

## Principais Funcionalidades

- **Scan Avançado de Rede:**  
  Varredura de IPs, ranges e sub-redes (CIDR), com detecção de portas abertas, banner grabbing, identificação de serviços e dispositivos.

- **Scan Rápido e Customizado:**  
  Modos rápidos para portas comuns ou customização total de alvos e portas.

- **Sniffer de Pacotes (PyShark):**  
  Captura de pacotes em tempo real, exportação para PCAP e visualização estilo Wireshark.

- **Deep Packet Inspection (DPI):**  
  Análise profunda dos pacotes, extraindo informações de protocolos, HTTP, TLS, DNS, etc.

- **Detecção de Anomalias:**  
  Usa Machine Learning (IsolationForest) para identificar padrões anômalos no tráfego de rede.

- **Fingerprinting de Sistemas Operacionais:**  
  Identificação do SO remoto via Nmap e análise de respostas TCP/IP.

- **Scanners Avançados:**  
  Detecção de serviços SMB, NetBIOS, SNMP, SSDP/UPnP, NFS, FTP, SSH, MySQL e coleta de banners.

- **Monitoramento em Tempo Real:**  
  Exibe pacotes capturados ao vivo, com destaque de cores.

- **Geração de Relatórios em PDF:**  
  Salva resultados e relatórios completos em PDF para documentação e auditoria.

- **Hash SHA256 de Arquivos:**  
  Ferramenta forense para calcular hash de arquivos suspeitos.

- **WHOIS e DNS:**  
  Consulta WHOIS e resolução DNS de domínios.

---

## Como Usar

1. **Pré-requisitos:**  
   - Python 3.8+  
   - Windows (preferencial), mas pode rodar em Linux com adaptações  
   - Permissões de administrador para sniffers/scanners

2. **Instalação:**  
   O próprio script instala as dependências automaticamente na primeira execução.

3. **Execução:**  
   Basta rodar o script principal:

   ```
   python Haven.py
   ```

4. **Menu Interativo:**  
   O menu oferece todas as opções de scan, análise, sniffer, relatórios e ferramentas forenses.

---

## Estrutura do Menu

- `[1]` **Scan avançado de rede**  
- `[2]` **Scan rápido (hosts e portas comuns)**
- `[3]` **Scan customizado (escolha IPs/portas)**
- `[4]` **Listar pontos de rede (gateway, DNS)**
- `[5]` **Sniffer de pacotes (PyShark/Wireshark-like)**
- `[6]` **Deep Packet Inspection (DPI)**
- `[7]` **Gerar relatório PDF do último resultado**
- `[8]` **WHOIS/DNS de domínio**
- `[9]` **Calcular hash SHA256 de arquivo**
- `[10]` **Monitorar tráfego de rede em tempo real**
- `[11]` **Detectar anomalias no tráfego de rede**
- `[12]` **Fingerprinting de SO (OS e TCP)**
- `[0]` **Sair**

---

## Exemplos de Uso

- **Scan de uma rede inteira:**  
  Escolha a opção 1 e informe o range ou CIDR, ex: `192.168.1.0/24`

- **Sniffer de pacotes:**  
  Opção 5, escolha a interface e quantidade de pacotes.

- **Detecção de anomalias:**  
  Opção 11, escolha interface e quantidade de pacotes para análise automática.

- **Relatório PDF:**  
  Após qualquer scan, use a opção 7 para salvar o resultado em PDF.

---

## Créditos

Desenvolvido por **SyraDevOps** & **TLS**  
Contato: [https://github.com/SyraDevOps](https://github.com/SyraDevOps)

---

## Aviso Legal

Este software é para uso educacional e de auditoria autorizada.  
**NUNCA** utilize em redes ou sistemas sem permissão explícita.

---