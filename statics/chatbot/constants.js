/**
 * chatbot/constants.js
 * Shared state variables, slash-command list, and scan-type registry.
 * All symbols live inside the Chatbot IIFE — this file is concatenated, not a module.
 *
 * FIXES:
 *   - Added /patch add to SLASH_CMDS (was missing — no way to manually store patches)
 */

  // ── Mutable state ──────────────────────────────────────────
  let _progressTimer   = null;
  let _selectedFmt     = 'html';
  let _currentTarget   = '';
  let _lastLatency     = null;
  let _lastTokens      = null;
  let _modelOk         = false;
  let _autocompleteIdx = -1;
  let _sortDir         = {};
  let _drawerMenuId    = null;

  let _modelName      = 'Detecting…';
  let _modelProvider  = 'Starting…';
  let _activeProvider = 'unknown';   // 'qwen' | 'llama' | 'deepseek' | 'rule-based'

  // ── Slash commands ─────────────────────────────────────────
  const SLASH_CMDS = [
    { cmd: '/graph',      hint: '/graph',                          desc: 'Open a graph in a new tab (OSINT Tree or Risk Dashboard)' },
    { cmd: '/scan',       hint: '/scan <ip>',                      desc: 'Scan a target (e.g. /scan 192.168.1.10)' },
    { cmd: '/patch',      hint: '/patch all',                      desc: '4-Layer patch resolution for all vulnerabilities' },
    { cmd: '/patch',      hint: '/patch <service> <port>',         desc: '4-Layer patch guide for a specific port' },
    { cmd: '/patch',      hint: '/patch CVE-XXXX-XXXX',            desc: 'Resolve patch for a specific CVE (Repo→Vendor→NVD→AI)' },
    { cmd: '/patch',      hint: '/patch add <cve> <pkg> <os> <cmd>',desc: 'Add a custom patch to the local patch repository' },  // ← NEW
    { cmd: '/fix',        hint: '/fix <service>',                  desc: 'Fix a service by name (e.g. /fix openssh)' },
    { cmd: '/advisory',   hint: '/advisory <CVE-ID>',              desc: 'Full advisory with confidence, source, and why it was chosen' },
    { cmd: '/remediate',  hint: '/remediate [critical|high|all]',  desc: 'Remediate vulnerabilities filtered by severity' },
    { cmd: '/cve',        hint: '/cve <CVE-ID>',                   desc: 'CVE intelligence via 4-layer resolver' },
    { cmd: '/vuln',       hint: '/vuln',                           desc: 'CVE dashboard — all vulnerabilities from last scan' },
    { cmd: '/report',     hint: '/report [pdf|html]',              desc: 'Export scan report' },
    { cmd: '/risk',       hint: '/risk',                           desc: 'Security score + risk breakdown (A-F grade)' },
    { cmd: '/export',     hint: '/export [pdf|html|json]',         desc: 'Export report in specified format' },
    { cmd: '/projects',   hint: '/projects',                       desc: 'List all scan projects and sessions' },
    { cmd: '/model',      hint: '/model',                          desc: 'Show AI model stack status' },
    { cmd: '/history',    hint: '/history',                        desc: 'Browse scan history (use sidebar)' },
    { cmd: '/settings',   hint: '/settings',                       desc: 'View configuration, model status, and patch resolution stats' },
    { cmd: '/clear',      hint: '/clear',                          desc: 'Clear chat history and session data' },
    { cmd: '/stop',       hint: '/stop',                           desc: 'Abort running scan' },
    { cmd: '/help',       hint: '/help',                           desc: 'Show all available commands' },
  ];

  const SCAN_TYPES = [
    // PORT SCANNING — Homepage featured
    { key: 'tcp_basic',          icon: '⚡', name: 'Quick TCP Scan',         category: 'port_scanning',    risk: 'moderate',   duration: '~30s',      recommended: true,  advanced: false, desc: 'Fast top-1000 TCP port discovery. Best for initial recon.',               cmd: 'nmap -sS -T4 --top-ports 1000' },
    { key: 'full_tcp',           icon: '🔓', name: 'Full TCP Scan',          category: 'port_scanning',    risk: 'aggressive', duration: '~5-15m',    recommended: true,  advanced: false, desc: 'Scans ALL 65535 TCP ports (-p-). Finds hidden services & backdoors.',      cmd: 'nmap -p- -sS -T4' },
    { key: 'udp_scan',           icon: '📡', name: 'Full UDP Scan',          category: 'port_scanning',    risk: 'aggressive', duration: '~30-60m',   recommended: true,  advanced: false, desc: 'All UDP ports. Detects DNS, SNMP, NTP, TFTP, VPN. Slow but essential.',   cmd: 'nmap -sU -p- --max-retries 2' },
    { key: 'stealth_syn',        icon: '🥷', name: 'Stealth SYN Scan',       category: 'port_scanning',    risk: 'moderate',   duration: '~3-5m',     recommended: true,  advanced: false, desc: 'Low-speed stealthy SYN scan. Evades basic IDS/firewall detection.',        cmd: 'nmap -sS -Pn -T2' },

    // ENUMERATION — Homepage featured
    { key: 'service_detect',     icon: '🔍', name: 'Service Detection',      category: 'enumeration',      risk: 'moderate',   duration: '~45s',      recommended: true,  advanced: false, desc: 'Identifies services and versions on open TCP ports.',                      cmd: 'nmap -sT -sV -T3' },
    { key: 'full_service_enum',  icon: '🔬', name: 'Full Service Enum',      category: 'enumeration',      risk: 'aggressive', duration: '~15-30m',   recommended: false, advanced: false, desc: 'Scans ALL ports (-p-) and detects versions, banners, daemon info.',        cmd: 'nmap -p- -sV -sS -T4' },
    { key: 'os_detect',          icon: '💻', name: 'OS Fingerprinting',      category: 'enumeration',      risk: 'moderate',   duration: '~60s',      recommended: false, advanced: false, desc: 'Identifies the target OS via TCP/IP stack fingerprinting.',                cmd: 'nmap -O --osscan-guess' },
    { key: 'banner_grab',        icon: '🪧', name: 'Banner Grabbing',        category: 'enumeration',      risk: 'moderate',   duration: '~45s',      recommended: false, advanced: false, desc: 'Grabs service banners for technology identification.',                     cmd: 'nmap -sT -sV --version-intensity 5 -T3' },
    { key: 'enum_scripts',       icon: '📜', name: 'Default Script Scan',    category: 'enumeration',      risk: 'moderate',   duration: '~90s',      recommended: false, advanced: false, desc: 'Runs safe NSE default scripts for deeper service enumeration.',            cmd: 'nmap -sC -sV' },
    { key: 'db_discovery',       icon: '🗄️', name: 'Database Discovery',     category: 'enumeration',      risk: 'moderate',   duration: '~30s',      recommended: false, advanced: false, desc: 'Scans MSSQL, MySQL, PostgreSQL, MongoDB, Redis ports.',                   cmd: 'nmap -p 1433,3306,5432,27017,6379 -sV' },

    // VULNERABILITY ASSESSMENT — Homepage featured
    { key: 'vuln_scan',          icon: '⚠️', name: 'Vulnerability Scan',     category: 'vuln_assessment',  risk: 'aggressive', duration: '~20-40m',   recommended: true,  advanced: false, desc: 'NSE vuln scripts across ALL ports (-p-). Detects CVEs and misconfigs.',    cmd: 'nmap --script vuln -p-' },
    { key: 'web_pentest',        icon: '🌐', name: 'Web Pentest Scan',       category: 'vuln_assessment',  risk: 'moderate',   duration: '~60s',      recommended: true,  advanced: false, desc: 'HTTP enum scripts on web ports. Finds admin panels, headers, directories.',cmd: 'nmap -p 80,443,8080,8000,8443 --script http-enum,http-title,http-headers' },
    { key: 'smb_audit',          icon: '🪟', name: 'SMB Security Audit',     category: 'vuln_assessment',  risk: 'moderate',   duration: '~30s',      recommended: false, advanced: false, desc: 'Enumerates SMB shares and users. Essential for Windows pentesting.',       cmd: 'nmap --script smb-enum-shares,smb-enum-users -p 445' },
    { key: 'ftp_audit',          icon: '📁', name: 'FTP Security Audit',     category: 'vuln_assessment',  risk: 'moderate',   duration: '~20s',      recommended: false, advanced: false, desc: 'Checks for anonymous FTP login and vsftpd backdoor.',                      cmd: 'nmap --script ftp-anon,ftp-vsftpd-backdoor -p 21' },
    { key: 'ssh_audit',          icon: '🔐', name: 'SSH Security Audit',     category: 'vuln_assessment',  risk: 'moderate',   duration: '~20s',      recommended: false, advanced: false, desc: 'Enumerates SSH auth methods and supported algorithms.',                    cmd: 'nmap --script ssh-auth-methods,ssh2-enum-algos -p 22' },

    // DISCOVERY
    { key: 'ping_sweep',         icon: '📶', name: 'Ping Sweep',             category: 'discovery',        risk: 'safe',       duration: '~15s',      recommended: false, advanced: false, desc: 'Discovers live hosts via ICMP echo requests.',                             cmd: 'nmap -sn' },
    { key: 'host_discovery',     icon: '🖧',  name: 'Host Discovery',         category: 'discovery',        risk: 'safe',       duration: '~20s',      recommended: false, advanced: false, desc: 'Multi-method host discovery without port scanning.',                       cmd: 'nmap -sn -PE -PS22,80,443 -PA80' },
    { key: 'arp_discovery',      icon: '🔗', name: 'ARP Discovery',          category: 'discovery',        risk: 'safe',       duration: '~10s',      recommended: false, advanced: false, desc: 'LAN ARP-based host discovery. Fastest for local networks.',                cmd: 'nmap -sn -PR' },

    // ADVANCED PENTESTING
    { key: 'ultimate_recon',     icon: '💀', name: 'Ultimate Recon',         category: 'advanced',         risk: 'very_noisy', duration: '~45-120m',  recommended: true,  advanced: true,  desc: 'All ports (-p-), OS+version, scripts, vuln scan. Very slow and noisy.',    cmd: 'nmap -p- -A -sV -O -sC --script vuln' },
    { key: 'aggressive_pentest', icon: '🚀', name: 'Aggressive Pentest',     category: 'advanced',         risk: 'very_noisy', duration: '~20-45m',   recommended: false, advanced: true,  desc: 'Full OS+version+traceroute+NSE across ALL ports (-p-).',                   cmd: 'nmap -A -p- -T4' },
    { key: 'firewall_evasion',   icon: '🛡️', name: 'Firewall Evasion',       category: 'advanced',         risk: 'aggressive', duration: '~3-5m',     recommended: false, advanced: true,  desc: 'ACK scan to map firewall rules and detect filtered ports.',                cmd: 'nmap -sA -T2' },
    { key: 'frag_scan',          icon: '🧩', name: 'Fragmented Packets',     category: 'advanced',         risk: 'aggressive', duration: '~2-5m',     recommended: false, advanced: true,  desc: 'IP fragmentation to evade packet-filter firewalls and IDS.',               cmd: 'nmap -sS -f -T3' },
    { key: 'decoy_scan',         icon: '🎭', name: 'Decoy Scan',             category: 'advanced',         risk: 'aggressive', duration: '~2-4m',     recommended: false, advanced: true,  desc: 'Masks real source IP with random decoys. Advanced evasion.',               cmd: 'nmap -sS -D RND:5 -T3' },
    { key: 'timing_manipulation',icon: '⏱️', name: 'Timing Manipulation',    category: 'advanced',         risk: 'moderate',   duration: '~10-20m',   recommended: false, advanced: true,  desc: 'Paranoid-speed scan (T1) to evade time-based IDS detection.',              cmd: 'nmap -sS -T1 --top-ports 100' },
  ];
