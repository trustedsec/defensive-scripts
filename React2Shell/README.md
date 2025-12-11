# React2Shell (CVE-2025-55182) Detection & Response

This repository contains detection rules, audit configurations, and hunting guidance for CVE-2025-55182 (React2Shell), a critical remote code execution vulnerability in React Server Components.

## Vulnerability Overview

**CVE-2025-55182** ("React2Shell") is a maximum severity (CVSS 10.0) unsafe deserialization vulnerability affecting:
- React 19.x (versions 19.0, 19.1.0, 19.1.1, 19.2.0)
- Next.js 15.x and 16.x (when using App Router)
- Other frameworks using React Server Components (Waku, Vite with RSC plugins)

The vulnerability allows **unauthenticated remote code execution** via a single crafted HTTP request. Applications are vulnerable even if they don't explicitly use server functions, as long as they support React Server Components.

### Active Exploitation
Within hours of public disclosure on December 3, 2025, multiple threat actors began exploiting this vulnerability:
- **China-nexus groups**: Earth Lamia, Jackpot Panda
- **North Korean actors**: Associated with "Contagious Interview" campaigns deploying EtherRAT malware
- **Opportunistic actors**: Cryptominers, credential harvesters, commodity backdoors

As of December 2025, over 77,000 Internet-exposed IP addresses have been identified as vulnerable, with at least 30 confirmed organizational breaches.

## Contents

This repository contains:

### Sigma Rules
Detection rules in Sigma format for identifying exploitation attempts and post-exploitation activity:
- HTTP exploitation detection (malicious POST requests with `next-action` headers)
- Suspicious process execution from Node.js
- Post-exploitation file and credential access
- Cloud metadata service access
- Shell configuration file modifications
- Cron job creation and modification
- EtherRAT-specific detection (blockchain-based C2, Node.js runtime downloads, multi-layer persistence)

### Linux Audit Rules
`auditd` configurations for monitoring:
- Reconnaissance commands (whoami, id, uname, hostname)
- Sensitive file access (/etc/passwd, SSH keys, AWS credentials)
- Shell configuration file modifications (.bashrc, .profile, .zshrc, etc.)
- Cron job manipulation
- Suspicious file writes (tmp directories, /dev/shm)
- Cloud metadata service access attempts
- Post-exploitation tools (nc, curl, wget, base64)

### Hunting Guidance
Scripts and commands for proactive threat hunting in your environment.

## Sigma Rules

The Sigma rules in this repository cover:

1. **react2shell_http_exploitation.yml** - Detects HTTP exploitation attempts via POST requests with React Server Action payloads
2. **react2shell_suspicious_node_execution.yml** - Identifies suspicious commands spawned by Node.js processes
3. **react2shell_file_credential_access.yml** - Catches post-exploitation file and credential access patterns
4. **react2shell_cloud_metadata_access.yml** - Detects attempts to access AWS/cloud metadata services
5. **react2shell_shell_config_modification.yml** - Monitors shell configuration file modifications for persistence
6. **react2shell_cron_creation.yml** - Detects cron job creation/modification by Node.js processes
7. **react2shell_suspicious_crontab.yml** - Identifies suspicious crontab command patterns
8. **etherrat_dropper_download.yml** - Detects EtherRAT dropper script downloads with fallback methods
9. **etherrat_ethereum_rpc_c2.yml** - Identifies EtherRAT's blockchain-based C2 communication
10. **etherrat_nodejs_download.yml** - Catches suspicious Node.js runtime downloads to unusual locations
11. **etherrat_multi_persistence.yml** - Detects simultaneous creation of multiple persistence mechanisms

### Converting Sigma Rules to Your SIEM

Sigma rules can be converted to various SIEM query languages using [sigmac](https://github.com/SigmaHQ/sigma) or [pySigma](https://github.com/SigmaHQ/pySigma):

```bash
# Convert to Splunk SPL
sigma convert -t splunk -f /path/to/rules/*.yml

# Convert to Elastic Query DSL
sigma convert -t elasticsearch -f /path/to/rules/*.yml

# Convert to Microsoft Sentinel KQL
sigma convert -t microsoft365defender -f /path/to/rules/*.yml

# Convert to QRadar AQL
sigma convert -t qradar -f /path/to/rules/*.yml
```

## Linux Audit Configuration

### Quick Deployment

1. Copy the audit rules to your system:
```bash
sudo cp audit-rules/react2shell.rules /etc/audit/rules.d/
```

2. Load the rules:
```bash
sudo auditctl -R /etc/audit/rules.d/react2shell.rules
```

3. Verify rules are loaded:
```bash
sudo auditctl -l | grep -E "recon_commands|passwd_access|shell_config|cron_modification"
```

4. Make rules persistent across reboots:
```bash
sudo systemctl restart auditd
```

### Monitoring Audit Logs

Query audit logs for suspicious activity:

```bash
# Search for reconnaissance commands
ausearch -k recon_commands --start today

# Check for unauthorized file access
ausearch -k passwd_access --start today
ausearch -k ssh_key_access --start today

# Look for shell configuration changes
ausearch -k shell_config_change --start today

# Review cron modifications
ausearch -k cron_modification --start today

# Check for spawned shells from Node.js
ausearch -k node_shell_spawn --start today

# Investigate cloud metadata access
ausearch -k cloud_metadata --start today
```

### Real-Time Monitoring

For real-time monitoring, use `auditctl` with follow mode:

```bash
sudo ausearch -k recon_commands -ts recent | tail -f
```

Or configure `auditd` to send alerts via syslog for immediate notification.

## Threat Hunting

### Quick Checks

```bash
# Check for React/Next.js processes
ps aux | grep -E "node|nodejs" | grep -v grep

# Look for suspicious POST requests in web server logs
grep -E "next-action|rsc-action-id" /var/log/nginx/access.log /var/log/apache2/access.log

# Search for base64-encoded commands in bash history
grep "base64" ~/.bash_history /root/.bash_history /home/*/.bash_history

# Check for unauthorized shell config modifications
find /home /root -name ".bashrc" -o -name ".bash_profile" -o -name ".profile" -o -name ".zshrc" -mtime -7

# Review recent cron jobs
ls -lat /etc/cron.d/ /var/spool/cron/crontabs/
```

### EtherRAT-Specific Hunting

```bash
# Look for hidden directories in .local/share
find /home /root -path "*/.local/share/.*" -type d 2>/dev/null

# Search for s.sh dropper script
find /tmp ~/.local/share -name "s.sh" -o -name "*.sh" -type f -mtime -7

# Check for downloads from nodejs.org
grep "nodejs.org" /var/log/syslog /var/log/messages

# Look for encrypted payloads
find /home /root /tmp -name "*.enc" -type f -mtime -7

# Monitor for Ethereum RPC connections
netstat -antp | grep -E "infura.io|alchemy.com|quicknode.com"
ss -tnp | grep -E "infura.io|alchemy.com|quicknode.com"

# Check for repeated download attempts (300-second loop)
journalctl -u <your-app-service> | grep -E "(curl|wget|python)" | awk '{print $1, $2, $3}' | uniq -c
```

### Enumerate All Cron Jobs

```bash
# Script to list all user crontabs
for user in $(cut -f1 -d: /etc/passwd); do 
    echo "=== Crontab for $user ==="
    crontab -u $user -l 2>/dev/null
done

# Check system-wide cron files
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
ls -la /var/spool/cron/crontabs/
```

## 🧪 Indicators of Compromise (IOCs)

### Behavioral Indicators

- POST requests with `next-action` or `rsc-action-id` headers
- Request bodies containing `$@`, `status":"resolved_model`, `then":"$`, `_response`, `_formData`
- Base64-encoded shell commands executed by Node.js
- Reconnaissance commands (whoami, id, uname) from application processes
- Access to /etc/passwd, SSH keys, AWS credentials by Node.js
- Multiple persistence mechanisms created within 60 seconds
- Node.js processes connecting to multiple Ethereum RPC endpoints in parallel
- High-frequency polling (every 500ms) to external infrastructure
- Download attempts repeating every 300 seconds (5 minutes)

### File Indicators

- Hidden directories in `~/.local/share/` (e.g., `.node-cache`, `.npm-data`)
- Shell scripts named `s.sh` or single-character names in `/tmp/` or `~/.local/share/`
- Encrypted payload files (`.enc` extension)
- Modified systemd user services in `~/.config/systemd/user/`
- Suspicious entries in shell profiles (.bashrc, .bash_profile, .profile, .zshrc)
- Standalone Node.js binaries in non-standard locations
- Base64-encoded commands in bash history

## Remediation

### Immediate Actions

1. **Patch immediately** - Update to patched versions:
   - React: 19.0.2+ or 19.1.2+ or 19.2.1+
   - Next.js: 14.3.0-canary.124+, 15.0.5+, 15.1.4+, 16.0.7+

2. **Deploy detection rules** - Implement the Sigma rules and audit configurations in this repository

3. **Hunt for compromise** - Use the hunting queries above to search for indicators

4. **Review logs** - Check web server, application, and system logs for exploitation attempts

5. **Audit persistence mechanisms**:
   - Shell configuration files (.bashrc, .profile, .zshrc, etc.)
   - Cron jobs (all users and system-wide)
   - Systemd services (system and user-level)
   - Startup scripts and autostart entries

6. **Rotate credentials** - If compromise is suspected, rotate:
   - AWS/cloud credentials
   - Application secrets and API keys
   - SSH keys
   - Database passwords

### If Compromise is Confirmed

1. **Isolate affected systems** - Disconnect from network or place behind WAF
2. **Preserve evidence** - Create memory dumps and disk images
3. **Analyze the full scope** - Check for lateral movement and data exfiltration
4. **Rebuild compromised systems** - Don't trust in-place remediation for RCE compromises
5. **Engage incident response** - Contact your security team or external IR provider

## References

### Official Advisories
- [AWS Security Blog - React2Shell Exploitation](https://aws.amazon.com/blogs/security/china-nexus-cyber-threat-groups-rapidly-exploit-react2shell-vulnerability-cve-2025-55182/)
- [React Team Security Advisory](https://react.dev/blog/2025/12/03/react-server-components-security-advisory)
- [Wiz.io Technical Deep-Dive](https://www.wiz.io/blog/nextjs-cve-2025-55182-react2shell-deep-dive)

### Malware Analysis
- [BleepingComputer - North Korean EtherRAT](https://www.bleepingcomputer.com/news/security/north-korean-hackers-exploit-react2shell-flaw-in-etherrat-malware-attacks/)
- [Sysdig - EtherRAT Analysis](https://sysdig.com/blog/etherrat-malware-react2shell/)

### Scanning Tools
- [Assetnote react2shell-scanner](https://github.com/assetnote/react2shell-scanner)
- [Shadowserver Foundation Scanning](https://www.shadowserver.org/)

## Contributing

Contributions are welcome! If you have additional detection rules, hunting queries, or IOCs related to React2Shell exploitation, please submit a pull request.

## License

These detection rules are provided as-is for defensive security purposes. Use responsibly and in accordance with applicable laws and regulations.



**Maintained by TrustedSec**  
*Protecting organizations through offensive security excellence*
