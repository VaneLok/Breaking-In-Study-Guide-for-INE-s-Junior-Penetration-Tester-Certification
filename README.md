# Breaking-In-Study-Guide-for-INE-Junior-Penetration-Tester-Certification
A focused **study guide** designed to prepare you for INE’s Junior Penetration Tester Certification (JPTC).


# eJPT Study Guide  

## Passive Information Gathering

## Lesson 1: Information Gathering  

### 📌 What is Information Gathering?  
Information gathering is the **first step of any penetration test**. It involves collecting information about an individual, company, website, or system that is being targeted.  

The **quality and quantity of information** you collect directly impacts your success in later penetration testing stages.  

---

### 🔑 Why it Matters  
- Builds a foundation for successful exploitation  
- Helps identify vulnerabilities and attack surfaces  
- Reduces time wasted in later stages by preparing with accurate intel  

---

### 🛠️ Types of Information Gathering  

#### Passive Information Gathering  
- Collecting data **without direct interaction** with the target  
- Examples:  
  - Google searches  
  - Public social media profiles  
  - WHOIS records  
  - DNS enumeration (indirect)  
- ✅ No direct risk of detection  

#### Active Information Gathering  
- Collecting data by **directly engaging** with the target system  
- Examples:  
  - Port scanning (Nmap)  
  - Banner grabbing  
  - Ping sweeps  
  - DNS zone transfers  
- ⚠️ Requires explicit authorization (legal/ethical requirement)  

---

### 🔍 What Information Are We Looking For?  

#### Passive Information Gathering  
- Identifying IP addresses & DNS information  
- Identifying domain names and domain ownership details  
- Identifying email addresses and social media profiles  
- Identifying web technologies used on target sites  
- Identifying subdomains  

#### Active Information Gathering  
- Discovering open ports on target systems  
- Learning about the internal infrastructure of a target network/organization  
- Enumerating information directly from target systems  

---

### 📚 Key Takeaways  
- **More information = better results** in later stages  
- Always **start with passive methods** to remain stealthy  
- Switch to **active methods only with authorization**  
- Document all findings carefully for reporting  
 

## Lesson 2: Website Recon & Footprinting  

### 📌 What is Website Recon & Footprinting?  
Website reconnaissance (recon) and footprinting is the process of gathering detailed information about a website and its infrastructure.  
The goal is to **map out the target’s digital footprint** to uncover hidden resources, technologies, and potential entry points.  

---

### 🔑 Why it Matters  
- Identifies attack surfaces specific to web applications  
- Reveals hidden directories, files, and technologies  
- Helps link digital assets (emails, phone numbers, addresses) to the organization  
- Provides a roadmap for web application testing  

---

### 🛠️ What Information Are We Looking For?  
- IP addresses of web servers  
- Directories hidden from search engines  
- Names of people tied to the organization  
- Email addresses & phone numbers  
- Physical addresses (OSINT correlation)  
- Web technologies in use (CMS, frameworks, servers, etc.)  

---

### 🌐 Understanding DNS  
**DNS (Domain Name System):** Translates domain names (e.g., `example.com`) into IP addresses that computers use.  

**How it Works:**  
1. User types a domain into the browser.  
2. DNS query is sent to a resolver.  
3. The resolver contacts root, TLD, and authoritative servers.  
4. The final IP is returned to the user’s browser.  

👉 Recon on DNS can reveal subdomains, mail servers, and infrastructure details.  

---

### 📄 Key Files for Recon  
- **robots.txt** → Lists paths that site owners don’t want indexed by search engines (can expose sensitive directories).  
- **sitemap.xml** → Provides structured information about website pages (often reveals hidden or forgotten content).  

---

### 🧩 Recon Tools & Add-ons  

#### Browser Extensions  
- **BuiltWith (Firefox/Chrome)** → Identifies frameworks, CMS, hosting, analytics.  
- **Wappalyzer** → Detects technologies (web servers, databases, programming languages).  

#### Command-Line Tools  
- **WhatWeb** → Built into Kali Linux; fingerprints web technologies.  

- **HTTrack** → A website mirroring tool that downloads entire sites for offline analysis.  
  - Mirroring allows you to browse the site locally as if it were online.  
  - **Certain mirrored files may reveal interesting information**, such as:  
    - Hidden directories or pages not easily found through browsing  
    - Configuration or backup files accidentally left accessible  
    - Old versions of scripts or resources that show past functionality or credentials  
  - Example usage (mirror site to local folder):  
    ```bash
    httrack http://example.com -O ./example_mirror
    ```  
    After mirroring, inspect the folder `./example_mirror` to find hidden files or archived pages.

- **grep** → Search utility for scanning mirrored/downloaded files.  
  - Useful for locating credentials, API keys, emails, or other sensitive strings in large file sets.  
  - Example usage (recursive + case-insensitive):  
    ```bash
    grep -Ri "password" ./example_mirror
    ```  
  - Common search patterns to try after mirroring:  
    - `password`  
    - `api_key` / `api-key` / `apikey`  
    - `token`  
    - `secret`  
    - `passwd`  
    - `config` / `config.php` / `wp-config.php`  

---

### 🧾 grep Mini Cheat Sheet  

| Flag | Meaning | Example |
|------|---------|---------|
| `-R` or `-r` | Recursive search through directories | `grep -R "password" ./example_mirror` |
| `-i` | Case-insensitive match | `grep -Ri "apikey" ./example_mirror` |
| `-n` | Show line numbers in results | `grep -Rin "token" ./example_mirror` |
| `--color=auto` | Highlight matches in output | `grep -R --color=auto "secret" ./example_mirror` |
| `-E` | Extended regex (use multiple patterns) | `grep -R -E "password|passwd|pwd" ./example_mirror` |
| `-l` | List filenames that match (no content) | `grep -Ril "api_key" ./example_mirror` |
| `-A <n>` / `-B <n>` | Show N lines After / Before match for context | `grep -R -n -A 3 "password" ./example_mirror` |

---

### ▶️ Practical Workflow (copy-ready)  
1. Mirror the site with HTTrack:  
    ```bash
    httrack http://example.com -O ./example_mirror
    ```  
2. Search for common sensitive keywords:  
    ```bash
    grep -Rin --color=auto -E "password|passwd|api_key|token|secret" ./example_mirror
    ```  
3. List files that matched (quick overview):  
    ```bash
    grep -Ril "api_key" ./example_mirror
    ```  
4. Inspect matched files with a pager/editor:  
    ```bash
    less ./example_mirror/path/to/file.html
    ```  

---

### 📚 Key Takeaways  
- Website recon maps out the **public-facing attack surface** and uncovers hidden resources.  
- **HTTrack** mirroring lets you perform offline analysis and may reveal hidden/backed-up files.  
- **grep** is an essential post-mirroring tool to rapidly identify sensitive strings across many files.  
- Combine browser add-ons, online recon, mirroring, and local analysis for full coverage.  


## Lesson 3: WHOIS Enumeration  

### 📌 What is WHOIS Enumeration?  
WHOIS enumeration is the process of retrieving **publicly available registration details** about a domain name.  
This information can reveal ownership, administrative contacts, and technical details about the target.  

---

### 🔑 Why it Matters  
- Provides insight into domain ownership and organizational details  
- Can reveal administrative contacts (emails, phone numbers)  
- May expose infrastructure (registrars, DNS servers, IP ranges)  
- Useful for correlating domains during footprinting  

---

### 🛠️ What Information Can WHOIS Reveal?  
- Domain ownership (individual or company)  
- Registration & expiration dates  
- Registrar details  
- Administrative and technical contact information  
- Name servers (helpful for further recon)  

⚠️ **Important:** Many domains today use **privacy services (e.g., Cloudflare, WhoisGuard)**.  
When enabled, the real owner’s details are replaced with **generic or redacted entries**.  

---

### 🌐 Example Target for Practice  
- **zonetransfer.me** → A practice domain often used for DNS & WHOIS exercises.  

---

### 📚 Key Takeaways  
- WHOIS enumeration is a **passive reconnaissance technique**. 
- Data may be **hidden behind privacy protections**, but it can still give useful leads (registrar, name servers, dates).  
- Combine WHOIS results with **DNS recon** and **OSINT tools** for a fuller target profile.  
 

## Lesson 4: Website Footprinting with Netcraft  

### 📌 What is Netcraft?  
**Netcraft** is an online reconnaissance tool that gathers information about a target domain.  
It provides details on hosting, technologies, DNS, and sometimes even historical changes to the site.  

---

### 🔑 Why it Matters  
- Offers quick insights into a domain without direct scanning  
- Can reveal hosting providers, SSL certificates, and server technologies  
- Useful for building an **initial profile of a target website**  

---

### 🛠️ What Information Can Netcraft Provide?  
- Hosting provider and IP addresses  
- DNS information  
- SSL/TLS certificate details  
- Web technologies and frameworks  
- Historical site data (sometimes old infrastructure)  

---

### 🌐 Example Usage  
- Visit: [https://searchdns.netcraft.com](https://searchdns.netcraft.com)  
- Enter the target domain (e.g., `example.com`) to view results.  

---

### 📚 Key Takeaways  
- Netcraft is a **passive reconnaissance tool**.  
- It provides a quick snapshot of a domain’s hosting and technology stack.  
- Combine Netcraft findings with WHOIS and DNS recon for stronger profiling.  
 

## Lesson 5: DNS Recon  

### 📌 What is DNS Reconnaissance?  
DNS reconnaissance is the process of collecting information about a target’s **Domain Name System (DNS)** records.  
This helps identify hosts, subdomains, mail servers, and other infrastructure linked to the target domain.  

---

### 🔑 Why it Matters  
- DNS records can reveal hidden subdomains and services  
- Helps map the target’s internal and external infrastructure  
- Assists in identifying possible attack vectors (e.g., misconfigured records, exposed hosts)  

---

### 🛠️ Tools for DNS Recon  

#### **DNS Recon** (Kali tool)  
- Command-line tool for DNS enumeration  
- Capabilities:  
  - Standard record enumeration (A, MX, NS, TXT)  
  - Subdomain brute forcing  
  - Zone transfer testing  
  - Reverse lookups  

#### **DNS Dumpster** (Online tool)  
- Free web-based tool for passive domain lookups  
- Provides:  
  - Subdomain mapping  
  - IP addresses  
  - Technology fingerprints  
- Great for quick, visual mapping of a domain  

---

### 📚 Key Takeaways  
- DNS recon reveals **critical infrastructure details** tied to a domain.  
- Tools like `dnsrecon` (active) and **DNSdumpster** (passive) complement each other.  
- Always check for misconfigurations such as **zone transfers**, as they can expose sensitive data.  


## Lesson 6: WAF With wafw00f  

### 📌 What is WAF With wafw00f?  
**wafw00f** is a reconnaissance tool that detects and fingerprints **Web Application Firewalls (WAFs)** protecting a target website by analyzing HTTP responses and behavior patterns.  

---

### 🔑 Why it Matters  
- Confirms whether a WAF is present  
- Identifies the WAF vendor/technology (e.g., Cloudflare, Akamai, F5, ModSecurity)  
- Informs testing strategy (rate limits, payload shaping, bypass approaches)  
- Reduces blocks by avoiding scans that the WAF will immediately filter  

---

### 🛠️ What Information Are We Looking For?  
- Presence or absence of a WAF  
- Specific WAF product/family and confidence level  
- Distinct response characteristics (status codes, headers, cookies, challenges)  
- Observed protections (rate limiting, geo/IP blocks, CAPTCHAs)  

**Example command:**  
```bash
wafw00f https://example.com
```  

---

### 📚 Key Takeaways  
- wafw00f is a **low-impact detection step** to run before active scans.  
- Knowing the WAF and its behavior helps **adapt tooling and payloads**.  
- Combine wafw00f results with **DNS/WHOIS and tech fingerprinting** for a fuller profile.  
 

## Lesson 7: Subdomain Enumeration With Sublist3r  

### 📌 What is Sublist3r?  
**Sublist3r** is a Python tool designed to enumerate subdomains of websites using **OSINT techniques**.  
It helps penetration testers and bug bounty hunters collect and gather subdomains for their target domain.  

Sublist3r works by querying multiple search engines and services to discover subdomains, and can also perform brute-force subdomain enumeration via the integrated **subbrute** module.  

---

### 🔑 Why it Matters  
- Identifies hidden or forgotten subdomains  
- Maps a larger attack surface of the target organization  
- Helps correlate infrastructure across different hosts  
- Provides reconnaissance data for further active scanning  

---

### 🛠️ What Information Are We Looking For?  
- Subdomains linked to the target domain  
- Services tied to those subdomains (web apps, mail, APIs, staging environments)  
- Possible entry points that aren’t exposed via the main website  

---

### 📦 About Sublist3r  
- Written in **Python**  
- Uses OSINT sources such as:  
  - Google, Yahoo, Bing, Baidu, Ask  
  - Netcraft, VirusTotal, ThreatCrowd, DNSdumpster, ReverseDNS  
- Integrated with **subbrute** to increase coverage through brute-force enumeration  
- Brute-force uses an improved wordlist by *TheRook* (author of subbrute)  

---

### 📊 Usage Options  

| Short Form | Long Form      | Description                                              |  
|------------|---------------|----------------------------------------------------------|  
| -d         | --domain      | Domain name to enumerate subdomains of                   |  
| -b         | --bruteforce  | Enable the subbrute brute-force module                   |  
| -p         | --ports       | Scan the found subdomains against specific TCP ports     |  
| -v         | --verbose     | Enable verbose mode and display results in real-time     |  
| -t         | --threads     | Number of threads to use for subbrute brute-force        |  
| -e         | --engines     | Specify a comma-separated list of search engines         |  
| -o         | --output      | Save the results to a text file                          |  
| -h         | --help        | Show the help message and exit                           |  

---

### ▶️ Example Commands  

Run Sublist3r against a domain:  
```bash
sublist3r -d example.com
```  

Save results to a text file:  
```bash
sublist3r -d example.com -o subdomains.txt
```  

Enable brute-force with subbrute:  
```bash
sublist3r -d example.com -b -t 50
```  

---

### 📚 Key Takeaways  
- Sublist3r is a **passive + brute-force hybrid tool** for subdomain enumeration.  
- It leverages **search engines and OSINT sources** for wide coverage.  
- With the **subbrute module**, it can brute-force subdomains using wordlists.  
- Always review discovered subdomains for **hidden services** that may expose vulnerabilities.  


## Lesson 8: Google Dorks  

### 📌 What is Google Dorking?  
**Google Dorking** (also known as *Google-fu* or *Google hacking*) is the use of advanced search operators in Google to discover information that is not easily visible through normal browsing.  
It is a form of **passive reconnaissance** that leverages publicly available data indexed by search engines.  

---

### 🔑 Why it Matters  
- Helps uncover **sensitive information** accidentally exposed online  
- Can reveal configuration files, login portals, and credentials  
- Identifies hidden directories, forgotten files, or indexed backups  
- Complements other OSINT methods with quick results  

---

### 🛠️ Google Dorks Cheat Sheet  

| Operator        | Description                                | Example Usage                                |  
|-----------------|--------------------------------------------|----------------------------------------------|  
| `site:`         | Restrict search to a specific domain        | `site:*.domainexample.com`                   |  
| `inurl:`        | Search for keywords in the URL path        | `inurl:admin`                                |  
| `filetype:`     | Find specific file types                   | `filetype:pdf site:*.domainexample.com`      |  
| `intitle:`      | Look for keywords in the page title        | `intitle:"index of"`                         |  
| `cache:`        | View cached version of a site              | `cache:domainexample.com`                    |  
| `" "` (quotes)  | Match exact phrase                        | `"confidential report"`                      |  

---

### ▶️ Example Commands  

Search for admin pages:  
```bash
site:*.domainexample.com inurl:admin
```  

Search for PDF files on a domain:  
```bash
site:*.domainexample.com filetype:pdf
```  

Look for exposed authentication files:  
```bash
inurl:auth_users_file.txt
```  

Look for exposed password files:  
```bash
inurl:password.txt
```  

Search for open directory listings:  
```bash
intitle:"index of"
```  

View cached pages from Google:  
```bash
cache:domainexample.com
```  

---

### 🧰 Additional Resources  
- **Wayback Machine (archive.org)** → Explore historical versions of websites  
- **Google Hacking Database (GHDB)** → Curated collection of powerful Google dorks  

---

### 📚 Key Takeaways  
- Google Dorking is a **powerful passive recon technique**.  
- Use operators like `site:`, `inurl:`, `filetype:`, `intitle:` to refine results.  
- Quotation marks `" "` force exact matches in searches.  
- Combine Google Dorks with tools like the **Wayback Machine** and **GHDB** for deeper recon.  


## Lesson 9: Email Harvesting With theHarvester  

### 📌 What is theHarvester?  
**theHarvester** is a simple yet powerful OSINT tool used during the **reconnaissance stage** of penetration testing and red team assessments.  
It helps map a domain’s external threat landscape by collecting information from public sources.  

---

### 🔑 Why it Matters  
- Identifies **email addresses, usernames, subdomains, and IPs** tied to a target domain  
- Helps reveal the attack surface for phishing, credential stuffing, or direct exploitation  
- Uses multiple OSINT data sources, making it highly effective in early recon  
- Provides a foundation for **social engineering** and deeper technical testing  

---

### 🛠️ What Information Are We Looking For?  
- Email addresses belonging to the target organization  
- Associated subdomains and IP addresses  
- Public URLs linked to the target  
- Infrastructure data via third-party sources (e.g., Shodan)  

---

### 📊 Usage Options Cheat Sheet  

| Option   | Description                                       | Example Usage                                |  
|----------|---------------------------------------------------|----------------------------------------------|  
| `-d`     | Specify the target domain                         | `-d example.com`                             |  
| `-l`     | Limit the number of results                       | `-l 500`                                     |  
| `-b`     | Choose data source (Google, Bing, Yahoo, Shodan)  | `-b google`                                  |  
| `-f`     | Save output to an HTML or XML file                | `-f results.html`                            |  
| `-s`     | Specify the start result number                   | `-s 0`                                       |  
| `-h`     | Display help                                      | `-h`                                         |  

---

### ▶️ Example Commands  

Search Google for emails tied to a domain:  
```bash
theHarvester -d example.com -b google
```  

Search Bing with a result limit of 500:  
```bash
theHarvester -d example.com -b bing -l 500
```  

Save results to a file:  
```bash
theHarvester -d example.com -b google -f harvest_results.html
```  

Use Shodan as a data source (requires API key):  
```bash
theHarvester -d example.com -b shodan -l 100
```  

---

### 🌐 Supported Data Sources  

theHarvester can pull results from multiple OSINT providers, including:  

- **Search Engines:** Google, Bing, Yahoo, DuckDuckGo, Baidu  
- **Social Networks / Repositories:** LinkedIn, GitHub, Twitter (limited)  
- **Security Services:** Shodan, Virustotal, Hunter.io  
- **Public Repositories:** DNSdumpster, ThreatCrowd, Netcraft  
- **Other Modules:** pgp (for email PGP key servers), crt.sh (for SSL/TLS certs)  

⚠️ Some of these require API keys (e.g., **Shodan, Virustotal, Hunter.io**).  

---

### 📚 Key Takeaways  
- theHarvester is a **go-to tool for OSINT-based email and subdomain harvesting**.  
- Supports a wide range of data sources, from **search engines to security services**.  
- Great for **reconnaissance before phishing campaigns** or credential testing.  
- Always secure API keys (e.g., Shodan, Virustotal, Hunter.io) before running advanced modules.  
 

## Lesson 10: Leaked Password Databases  

### 📌 What are Leaked Password Databases?  
Leaked password databases are collections of **usernames, emails, and passwords** that have been exposed due to data breaches.  
These credentials often circulate on the dark web or in public breach repositories.  
Attackers and penetration testers can use these leaks to assess password reuse and organizational risk.  

---

### 🔑 Why it Matters  
- Exposed credentials are one of the **most common entry points** for attackers  
- Employees often reuse passwords across personal and corporate accounts  
- Helps identify **at-risk users** before attackers exploit them  
- Essential for building password security policies and training users  

---

### 🛠️ Tools for Checking Leaked Credentials  

#### **Have I Been Pwned (HIBP)**  
- Website: [https://haveibeenpwned.com](https://haveibeenpwned.com)  
- Allows you to check if an **email address or password** has appeared in known data breaches  
- Offers an API for automated checks (requires API key for full usage)  

**Example (manual check):**  
```bash
# Visit website and enter email
https://haveibeenpwned.com
```  

**Example (API usage with curl):**  
```bash
curl -H "hibp-api-key: YOUR_API_KEY" \
"https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com"
```  

---

### 🌐 Other Resources  
- **DeHashed** → Paid breach database search engine ([https://dehashed.com](https://dehashed.com))  
- **LeakCheck** → Breach lookup service with API  
- **IntelligenceX** → Advanced search engine for breaches and leaks  

---

### 📚 Key Takeaways  
- Leaked password databases expose **credentials from past breaches**.  
- Tools like **Have I Been Pwned** allow passive recon on user accounts.  
- APIs (HIBP, DeHashed, LeakCheck) can integrate into **automation workflows**.  
- Monitoring leaks helps defenders **enforce resets** and reduce credential reuse risks.  


# eJPT Study Guide 

## Active Information Gathering 

## Lesson 1 : DNS Zone Transfers  

### 📌 What is DNS?  
- **Domain Name System (DNS)** is a protocol that resolves **domain names/hostnames into IP addresses**.  
- Before DNS, users had to remember raw IP addresses. DNS makes the internet more user-friendly by mapping names → IPs.  
- A **DNS server (nameserver)** acts like a phone directory, storing mappings of domains to IPs.  
- Public DNS servers include:  
  - Cloudflare → `1.1.1.1`  
  - Google → `8.8.8.8`  

---

### 🗂️ Common DNS Record Types  

| Record | Purpose | Example |  
|--------|----------|---------|  
| `A`    | Maps hostname to IPv4 address | `example.com → 192.168.1.1` |  
| `AAAA` | Maps hostname to IPv6 address | `example.com → fe80::1` |  
| `NS`   | Reference to domain’s nameserver | `ns1.example.com` |  
| `MX`   | Mail server records | `mail.example.com` |  
| `CNAME`| Domain alias | `www → example.com` |  
| `TXT`  | Text record (SPF, verification) | `v=spf1 include:_spf.google.com` |  
| `HINFO`| Host information | OS & CPU type |  
| `SOA`  | Start of Authority | Domain authority details |  
| `SRV`  | Service locator records | `_sip._tcp.example.com` |  
| `PTR`  | Resolves IP → hostname (reverse lookup) | `192.168.1.1 → example.com` |  

---

### 🔍 DNS Interrogation  
**DNS interrogation** is the process of enumerating DNS records for a domain.  
It helps discover:  
- IP addresses  
- Subdomains  
- Mail server addresses  
- Infrastructure details  

---

### 📌 What is a DNS Zone Transfer?  
- **Zone transfer** = copying zone files from one DNS server to another.  
- Legitimate use: backup, load balancing, redundancy.  
- Misconfiguration risk:  
  - Attackers can retrieve **entire DNS zone file**  
  - Provides a **map of the organization’s infrastructure**  
  - May even expose **internal IP addresses**  

---

### 🛠️ Tools for DNS Enumeration  

#### **dnsenum**  
Brute-forces and enumerates DNS information.  
```bash
dnsenum example.com
```  

#### **dig**  
Performs DNS lookups, queries specific record types, and attempts zone transfers.  
```bash
dig ns example.com
dig axfr example.com @ns1.example.com
```  

#### **fierce**  
A domain scanner for finding subdomains and DNS misconfigurations.  
```bash
fierce --domain example.com
```  

---

### 📚 Key Takeaways  
- DNS translates **domain names ↔ IP addresses**, and records reveal valuable details.  
- DNS interrogation can expose **subdomains, mail servers, and infrastructure**.  
- Misconfigured **zone transfers** provide a **blueprint of the network**.  
- Tools like **dnsenum, dig, fierce** automate DNS enumeration and zone transfer attempts.  
 

## Lesson 2 : Host Discovery With Nmap  

### 📌 What is Host Discovery?  
Host discovery is the process of identifying **active devices** on a network.  
It helps penetration testers understand which machines are live and responding before moving to deeper scans.  

---

### 🔑 Why it Matters  
- Reveals which systems are **reachable and online**  
- Helps narrow down targets before running intensive scans  
- Identifies hidden hosts that may not respond to normal pings  
- Provides an early **network map** for further reconnaissance  

---

### 🛠️ Tools for Host Discovery  

#### **netdiscover**  
A simple ARP scanning tool used to discover live hosts on a local network.  

```bash
netdiscover -r 192.168.1.0/24
```  

#### **nmap**  
One of the most widely used tools for host discovery and port scanning.  

- **Ping Sweep (no port scan):**  
```bash
nmap -sn 192.168.1.0/24
```  

- **ARP Scan (faster for local LANs):**  
```bash
nmap -PR 192.168.1.0/24
```  

- **Disable DNS Resolution (faster scans):**  
```bash
nmap -sn -n 192.168.1.0/24
```  

---

### 📚 Key Takeaways  
- **Host discovery** identifies which devices are active in a network range.  
- `netdiscover` is ideal for quick ARP scans in local environments.  
- `nmap -sn` performs ping sweeps without scanning ports.  
- Use host discovery **before detailed scanning** to save time and reduce noise.  

## Lesson 3 : Port Scanning With Nmap  

### 📌 What is Port Scanning?  
Port scanning is the process of probing a host for **open, closed, or filtered ports** to identify available services.  
It is a fundamental part of penetration testing and network reconnaissance.  

---

### 🔑 Why it Matters  
- Reveals which services are running on a host  
- Helps identify potential entry points for exploitation  
- Supports OS fingerprinting and service detection  
- Provides context for deeper vulnerability assessments  

---

### 🛠️ Types of Nmap Scans  

| Scan Type                  | Command Example                         | Purpose                                              | Speed/Stealth |  
|-----------------------------|------------------------------------------|------------------------------------------------------|---------------|  
| **Full TCP Port Scan**     | `nmap -Pn -p- target.com`                | Scans all 65,535 TCP ports                          | ❌ Slow / ✅ Thorough |  
| **Fragmented Packets**     | `nmap -Pn -f target.com`                 | Evade simple firewalls/IDS by fragmenting packets    | ⚠️ Noisy / Bypass |  
| **UDP Scan**               | `nmap -Pn -sU target.com`                | Finds UDP services (DNS, SNMP, etc.)                | ❌ Slow / ✅ Important |  
| **Fast Scan + Version**    | `nmap -Pn -F -sV target.com`             | Top 100 ports with service version detection        | ✅ Fast / Moderate |  
| **Fast Scan + OS**         | `nmap -Pn -F -O target.com`              | Top 100 ports with OS fingerprinting                | ✅ Fast / Moderate |  
| **Combined Deep Scan**     | `nmap -Pn -F -sV -O -sC target.com`      | Service detection, OS detection, default NSE scripts| ❌ Slower / ✅ Detailed |  
| **Aggressive Service Scan**| `nmap -sV -T4 target.com`                | Detects versions with faster timing (Aggressive)    | ✅ Fast / ❌ Stealth |  

---

### ⏱️ Timing Templates  
Timing templates control how aggressive Nmap is with packet sending:  

- **`-T0` → Paranoid** (extremely slow, IDS evasion)  
- **`-T1` → Sneaky** (slow, stealthy)  
- **`-T2` → Polite** (reduced load)  
- **`-T3` → Normal** (default)  
- **`-T4` → Aggressive** (faster scans, less stealth)  
- **`-T5` → Insane** (very fast, noisy, risks accuracy)  

---

### ▶️ Example Commands  

Full TCP scan:  
```bash
nmap -Pn -p- target.com
```  

Fragmented packets scan:  
```bash
nmap -Pn -f target.com
```  

UDP scan:  
```bash
nmap -Pn -sU target.com
```  

Fast scan with service detection:  
```bash
nmap -Pn -F -sV target.com
```  

Fast scan with OS detection:  
```bash
nmap -Pn -F -O target.com
```  

Deep combined scan:  
```bash
nmap -Pn -F -sV -O -sC target.com
```  

Aggressive service detection scan:  
```bash
nmap -sV -T4 target.com
```  

---

### 📚 Key Takeaways  
- Nmap supports **TCP, UDP, service, and OS detection** scans.  
- Use `-p-` for **full port coverage**, but it is slower.  
- Use `-sU` for **UDP scanning**, which many admins overlook.  
- Combine flags (`-sV`, `-O`, `-sC`) for **deep reconnaissance**.  
- Timing templates (`-T0`–`-T5`) let you balance **speed vs stealth**.  
- Fragmentation (`-f`) may bypass weak firewalls/IDS, but is noisy in modern environments.  


# eJPT Study Guide 

## Networking Primer

## Lesson 1: Networking Fundamentals  

### 📌 What is Networking?  
Networking is the practice of connecting computers and devices so they can communicate and share resources.  
The **primary goal of networking** is to exchange information between systems — this exchange happens through **packets** and **protocols**.

---

### 📦 Packets  
Packets are the fundamental units of communication over a network.

- **Structure:** Every packet has two main parts:  
  - **Header** → protocol-specific metadata (addresses, flags, lengths, sequencing) that lets the receiver interpret and route the payload.  
  - **Payload** → the actual content being carried (e.g., part of an email, HTTP response body, file chunk).

- **Notes:**  
  - Packets are streams of bits transmitted as electrical/optical/radio signals (Ethernet, Wi-Fi, Fiber).  
  - Protocol headers differ by layer (Ethernet header, IP header, TCP/UDP header, application headers).

---

### 🌐 Network Protocols (Stateless vs Stateful)  
Protocols define the rules for communication between hosts. They can be **stateless** or **stateful**:

- **Stateless protocols**  
  - **Definition:** Each request is independent; the server does not retain session state between requests.  
  - **Example:** **UDP** (User Datagram Protocol) — single datagram delivery, no connection, no guaranteed order or delivery.  
  - **Use cases:** DNS queries, streaming, simple request/response where low latency matters.  
  - **Implications for testing:** Easier to spoof source IPs, harder to track session behaviour; fewer handshake artefacts for IDS/forensics.

- **Stateful protocols**  
  - **Definition:** The endpoints maintain session state across multiple messages (connection-oriented).  
  - **Example:** **TCP** (Transmission Control Protocol) — 3-way handshake, ordered delivery, retransmission, connection teardown.  
  - **Use cases:** HTTP (over TCP), SSH, SMTP.  
  - **Implications for testing:** Sessions provide richer fingerprinting (handshakes, sequence numbers); stateful firewalls can track and block non-stateful traffic.

- **Stateful vs Stateless Firewalls / Inspection**  
  - **Stateless firewall:** Filters packets based on simple rules (IP, port). No session tracking; faster but easier to bypass with crafted packets.  
  - **Stateful firewall / IPS:** Tracks connection state (e.g., TCP handshake) and inspects context. More accurate detection and blocking of anomalous traffic.

---

### 📚 The OSI Model  
The **OSI (Open Systems Interconnection)** model is a conceptual 7-layer framework that standardizes network functions:

| # | Layer (Name)       | Primary Function                                      | Typical Protocols / Examples |
|---|--------------------|--------------------------------------------------------|-------------------------------|
| 7 | **Application**    | Network services to applications / end-users          | HTTP, FTP, DNS, SMTP, SSH     |
| 6 | **Presentation**   | Data translation, encryption, compression             | SSL/TLS, MIME, JPEG           |
| 5 | **Session**        | Session/dialog management, synchronization            | NetBIOS, SMB, RPC             |
| 4 | **Transport**      | End-to-end communication, reliability, flow control   | TCP (stateful), UDP (stateless) |
| 3 | **Network**        | Logical addressing and routing                        | IP, ICMP, IPSec               |
| 2 | **Data Link**      | Framing, MAC addressing, error detection              | Ethernet, PPP, Switches       |
| 1 | **Physical**       | Physical transmission of raw bits                     | Cables, Fiber, Hubs, Wi-Fi    |

**Notes:**  
- The OSI model is a reference — many real-world protocols (the TCP/IP suite) map across these layers rather than matching exactly.  
- For penetration testing, layers 3–7 are the most frequently relevant (routing, transport behavior, services, and application logic).

---

### 🧭 Penetration Testing Methodology (Context)  
Networking fundamentals map directly into common pentest phases:

- **Information Gathering (Passive & Active):** DNS recon, WHOIS, OSINT.  
- **Scanning / Network Mapping:** Host discovery (ICMP, ARP), port scanning (TCP/UDP), service/OS detection.  
- **Enumeration:** Service-specific enumeration, credential harvesting, directory/file discovery.  
- **Exploitation & Post-Exploitation:** Use protocol/service behavior to gain access and move laterally.  
- **Reporting:** Document network-level findings (exposed services, weak protocols, misconfigurations).

---

### 📚 Key Takeaways  
- **Packets** = Header (metadata) + Payload (data). Understanding both is essential for traffic analysis.  
- **Stateless (UDP)** vs **Stateful (TCP)** matters for how services behave, how firewalls handle traffic, and how tests should be designed.  
- The **OSI model** helps organize where a problem or control lives (physical → application).  
- Networking fundamentals are foundational for reconnaissance, scanning, fingerprinting, exploitation, and post-exploitation in penetration testing.  

# Lesson 2: Network Layer  

## 📌 What It Does

The **Network Layer (Layer 3)** of the OSI model is responsible for:  
- Logical addressing  
- Routing and forwarding packets across different networks  
- Determining the **optimal path** for data to travel from source to destination  
- Abstracting the underlying physical networks to create a **cohesive internetwork**

---

## 🌐 Key Protocols at the Network Layer  
- **Internet Protocol (IP)**  
  - **IPv4** → 32-bit addressing (widely used, foundation of the Internet)  
  - **IPv6** → 128-bit addressing (developed to overcome IPv4 limitations, exponentially larger space)  
- **Internet Control Message Protocol (ICMP)**  
  - Used for error reporting and diagnostics (e.g., `ping`, `traceroute`)  

---

## 🔑 Internet Protocol (IP)  
- Central protocol forming the foundation of the Internet  
- Handles **logical addressing, routing, fragmentation, and reassembly**  
- Provides standardized way to identify and locate hosts across networks  

### IP Functionality  
- **Logical Addressing**  
  - Unique identifiers for each device (IP addresses)  
  - Structured by **classes, subnets, and CIDR notation**  
- **Packet Structure**  
  - Consists of **Header + Payload**  
  - Header includes: source & destination IP, version, TTL, protocol type  

---

## 📦 IPv4 Header Fields  
| **Field** | **Purpose** |
|-----------|-------------|
| **Version (4 bits)** | Indicates version of IP (value = 4 for IPv4) |
| **Header Length (4 bits)** | Size of IPv4 header (min 20 bytes, max 60 bytes) |
| **Type of Service (8 bits)** | QoS control, DSCP, ECN |
| **Total Length (16 bits)** | Size of entire packet (max 65,535 bytes) |
| **Identification (16 bits)** | Used for packet fragmentation & reassembly |
| **Flags (3 bits)** | Control fragmentation (DF, MF bits) |
| **TTL (8 bits)** | Max hops before discard (decrements at each router) |
| **Protocol (8 bits)** | Identifies higher-layer protocol (TCP=6, UDP=17, ICMP=1) |
| **Source IP (32 bits)** | Sender’s IP address |
| **Destination IP (32 bits)** | Receiver’s IP address |

---

## 🏷️ Reserved IPv4 Address Ranges  
- **0.0.0.0 – 0.255.255.255** → "This" network  
- **127.0.0.0 – 127.255.255.255** → Loopback (local host)  
- **192.168.0.0 – 192.168.255.255** → Private networks  
- Full details → [RFC 5735](https://www.rfc-editor.org/rfc/rfc5735)  

---

## 📡 Additional IP Functionality  
- **Fragmentation & Reassembly**  
  - Splits large packets into smaller fragments (MTU handling)  
  - Receiving host reassembles original packet  
- **Addressing Types**  
  - **Unicast** → One-to-one communication  
  - **Broadcast** → One-to-all within subnet  
  - **Multicast** → One-to-many (selected group of devices)  
- **Subnetting**  
  - Divides a network into smaller sub-networks  
  - Enhances **efficiency** and **security**  

---

## ⚡ Related Protocols at Network Layer  
- **ICMP** → Diagnostics (`ping`, `traceroute`)  
- **DHCP** → Dynamically assigns IP addresses  

---

## 🧪 Wireshark Essentials (Network Layer)

### 🔎 Display Filters
- Show all IP traffic:
    ip
- Filter by a specific host:
    ip.addr == 192.168.1.10
- Show only ICMP (ping traffic):
    icmp
- Show only DHCP traffic:
    bootp
- Find fragmented packets:
    ip.flags.mf == 1

### 🎯 Capture Filters (set before recording)
- Capture only traffic to/from a specific host:
    host 8.8.8.8
- Capture only ICMP (ping):
    icmp
- Capture only traffic on port 80 (HTTP):
    port 80

---

## 📚 Quick Review Questions  
1. What is the main responsibility of the **Network Layer (Layer 3)?**  
2. Difference between **IPv4** and **IPv6**?  
3. What is the purpose of the **TTL field** in the IPv4 header?  
4. Name the three **types of IP addressing**.  
5. Which protocol is used for **error reporting and diagnostics** at Layer 3?  


## Lesson 3: Transport Layer

## 📌 What It Does

- Ensures **end-to-end communication** between two devices on a network  
- Provides **reliable and ordered delivery** of data  
- Handles **error detection, flow control, and segmentation** of data 

---

### 🔑 Key Responsibilities
- Provides **end-to-end communication** between devices  
- Ensures **reliable and ordered delivery** of data  
- Handles **error detection, flow control, and retransmission**  
- Segments large messages into smaller chunks for transmission  

---

### 🚦 Transport Layer Protocols
- **TCP (Transmission Control Protocol)** → Connection-oriented, reliable, ensures ordered delivery  
- **UDP (User Datagram Protocol)** → Connectionless, faster, no guarantee of reliability or order  

---

### ⚙️ TCP (Transmission Control Protocol)
- **Connection-Oriented:** Establishes a connection before data transfer  
- **Reliability:** Uses ACKs and retransmission to guarantee delivery  
- **Ordered Data Transfer:** Ensures packets arrive in correct order  

---

### 🚩 TCP Control Flags
Flags used to manage connections:

- **SYN** → Synchronize (start a connection)  
- **ACK** → Acknowledge receipt of data  
- **FIN** → Terminate a connection  

**Connection Lifecycle:**  
- Establishing a Connection → SYN, SYN-ACK, ACK  
- Data Transfer → Packets sent with sequence numbers and ACKs  
- Termination → FIN, ACK exchange  

---

### 🤝 TCP 3-Way Handshake
Process to establish a connection:  
1. **SYN** → Client requests a connection  
2. **SYN-ACK** → Server acknowledges and responds  
3. **ACK** → Client confirms and connection established  

After handshake, data transmission begins.

---

### 🔢 TCP Port Ranges
- **Well-Known Ports (0–1023):** Standardized services (e.g., 80 HTTP, 443 HTTPS, 22 SSH, 25 SMTP)  
- **Registered Ports (1024–49151):** Assigned to software/apps (e.g., 3389 RDP, 3306 MySQL, 8080 HTTP-alt, 27017 MongoDB)  
- **Dynamic/Private Ports (49152–65535):** Temporary, used for client connections  

Maximum port number: **65,535**

---

### ⚡ UDP (User Datagram Protocol)
- **Connectionless:** No handshake, each packet independent  
- **Unreliable:** No guarantees of delivery or retransmission  
- **Stateless:** Does not maintain session info  
- **Fast:** Used in real-time apps (VoIP, gaming, streaming)  

---

### 📊 TCP vs UDP

| Feature       | UDP                        | TCP                               |
|---------------|----------------------------|-----------------------------------|
| **Connection** | Connectionless              | 3-Way Handshake (connection-oriented) |
| **Reliability** | Unreliable, no guarantees   | Reliable, retransmission + ordering |
| **Header Size** | Small, low overhead         | Larger header size                |
| **Applications** | VoIP, gaming, streaming    | HTTP, HTTPS, FTP, SMTP, Email     |

---

### 🔍 Useful Tools at Transport Layer
- **netstat -antp** → Show active connections, ports, and processes  
- **FTP / SFTP** → File transfers (unencrypted vs encrypted)  
- **SMB** → File sharing over networks  
- **Encapsulation:** Ensures transport segments are wrapped inside IP packets  

---

### 📚 Key Takeaways  

- TCP = Reliable, ordered, connection-oriented  
- UDP = Fast, lightweight, connectionless, stateless  
- Port numbers define services and help attackers/defenders identify traffic  
- Tools like `netstat`, FTP/SFTP, and SMB are crucial for practical reconnaissance  


# eJPT Study Guide 

## Host Discovery

## Lesson 1: Network Mapping  

### 📌 What is Network Mapping?  
- In penetration testing, **network mapping** is the process of discovering and identifying devices, hosts, and infrastructure within a target network.  
- Pentesters use network mapping as a crucial step to:  
  - Gather information about the network’s layout  
  - Understand its architecture  
  - Identify potential entry points for further exploitation  

---

### 🎯 Why Map a Network?  
- Provides a clear understanding of how many systems exist and their functional role.  
- Helps identify active hosts and their corresponding IP addresses.  
- Supports enumeration by showing which services and operating systems are running.  

---

### 🛠️ Objectives of Network Mapping  
- **Discovery of Live Hosts** → Identify active devices and hosts on the network.  
- **Open Ports & Services** → Determine which ports are open and what services run on them.  
- **Network Topology Mapping** → Create diagrams of routers, switches, firewalls, and other infrastructure.  

---

### 🔎 Nmap (Network Mapper)  
- **Nmap** is an open-source network scanning tool used for:  
  - Discovering hosts and services  
  - Finding open ports  
  - Identifying potential vulnerabilities  
- It’s widely used by pentesters, sysadmins, and security researchers.  

#### ⚙️ Nmap Functionality  
- **Host Discovery** → ICMP echo requests, ARP requests, TCP/UDP probes  
- **Port Scanning** → Identifies open ports on hosts  
- **Service Version Detection** → Determines software versions running on open ports  
- **OS Fingerprinting** → Attempts to identify operating systems based on scanning characteristics  

---

### 📚 Key Takeaways  
- Network mapping = the **bridge between passive and active recon**.  
- Essential for identifying live hosts, services, and the overall network structure.  
- **Nmap** is the go-to tool for network mapping due to its versatility and power.  


## Lesson 2: Host Discovery Techniques  

In penetration testing, **host discovery** is a crucial phase to identify live hosts on a network before deeper exploration and vulnerability assessment.  

The choice of discovery technique depends on factors such as:  
- Network characteristics  
- Stealth requirements  
- Security controls in place  
- Goals of the penetration test  

---

### 🔑 Key Techniques  

- **ICMP Ping (Ping Sweeps)**  
  - Sends ICMP Echo Requests to a range of IPs.  
  - ✅ Quick, widely supported method.  
  - ❌ Firewalls/hosts may block ICMP traffic.  

- **ARP Scanning**  
  - Uses Address Resolution Protocol (ARP) to discover hosts in the same broadcast domain.  
  - ✅ Highly effective in local networks.  

- **TCP SYN Ping (Half-Open Scan)**  
  - Sends TCP SYN packets (commonly to port 80).  
  - If alive, host replies with **SYN-ACK**.  
  - ✅ Stealthier than ICMP.  
  - ❌ Some hosts may drop SYN packets.  

- **UDP Ping**  
  - Sends UDP packets to specific ports to detect active hosts.  
  - Useful when ICMP/TCP probes are blocked.  

- **TCP ACK Ping**  
  - Sends TCP ACK packets.  
  - A **TCP RST** response indicates host is alive.  
  - ✅ Works when SYN might be filtered.  

- **SYN-ACK Ping**  
  - Sends SYN-ACK packets.  
  - A **TCP RST** response confirms host is active.  

---

### ⚖️ Pros & Cons of Key Methods  

- **ICMP Ping**  
  - ✅ Fast and simple  
  - ❌ Easily blocked, detectable  

- **TCP SYN Ping**  
  - ✅ Stealthier, may bypass firewalls allowing outbound connections  
  - ❌ Some hosts ignore SYN probes  

---

### 📚 Key Takeaways  
- **No single “best” technique** → effectiveness depends on network defenses and testing goals.  
- ICMP, TCP, and UDP methods all have strengths depending on the scenario.  
- Stealthier techniques (e.g., SYN, ACK pings) are often used when ICMP is blocked.  

# Lesson 3 — Ping Sweeps 

## 📌 Quick Definition
Ping sweeps = **ICMP Echo Requests** sent across an IP range to identify live hosts.  
- **Echo Request** → Type **8**, Code **0**  
- **Echo Reply** → Type **0**, Code **0**

---

## ⚙ How Ping Sweeps Work (concise)
1. Send ICMP Echo Requests to a list/range of IPs.  
2. Alive hosts reply with ICMP Echo Replies.  
3. Record responding IPs as “up”; use other methods for non-responders.

---

## 🛠 Tools & Usage

### `ping` (single-host)
```bash
ping example.com
```

### `fping` (multi-host / subnet)
```bash
# Sweep a CIDR and show alive hosts
fping -a -g 10.10.23.0/24

# Read targets from a file and show alive hosts
fping -a -f targets.txt

# Set count (retries) and timeout (ms)
fping -c 3 -t 500 -g 192.168.1.0/24
```

**Common `fping` flags**
- `-a` → show alive hosts only  
- `-g` → CIDR/IP range sweep  
- `-f <file>` → read targets from file  
- `-c <n>` → number of pings per host  
- `-t <ms>` → timeout per ping (ms)  
- `-r <n>` → retries  
- `-b <bytes>` → payload size

---

## 🔁 Nmap Host Discovery Alternatives

| Option | Probe Type | Example | Use Case |
|--------|------------|---------|----------|
| `-PE`  | ICMP Echo Request | `nmap -sn -PE 10.0.0.0/24` | Standard ping |
| `-PP`  | ICMP Timestamp | `nmap -sn -PP 10.0.0.0/24` | Alternate ICMP probe |
| `-PM`  | ICMP Netmask | `nmap -sn -PM 10.0.0.0/24` | Rare cases |
| `-PS`  | TCP SYN Ping | `nmap -sn -PS80,443 10.0.0.0/24` | When ICMP blocked |
| `-PA`  | TCP ACK Ping | `nmap -sn -PA80 10.0.0.0/24` | SYN filtered |
| `-PU`  | UDP Ping | `nmap -sn -PU53 10.0.0.0/24` | UDP-based discovery |
| `-PR`  | ARP Scan | `nmap -sn -PR 192.168.1.0/24` | **Best for LANs** |

> Tip: ARP is the most reliable for local networks; TCP/UDP probes are useful when ICMP is filtered.

---

## ✅ When to Use Which Method
- **Use `fping`** for fast bulk ICMP sweeps on permissive networks (LANs, labs).  
- **Use `nmap -sn -PE`** for a standard ICMP host discovery scan.  
- **Switch to TCP/UDP probes (`-PS`, `-PA`, `-PU`)** when ICMP is filtered.  
- **Use ARP (`-PR`)** for local-subnet discovery — most reliable on LANs.  
- **Combine methods** (e.g., ARP + TCP SYN + UDP probe) for the most complete discovery.

---

## ⚖️ Drawbacks & Contingencies
- ICMP often filtered → false negatives possible.  
- Firewalls/IDS detect sweeps — be mindful of noise.  
- ARP scans don’t route (local-only).  
- Always follow rules of engagement and get explicit authorization.

---

## 📚 Key Takeaways
- Memorize ICMP codes: Request = **8**, Reply = **0**.  
- `fping` = scalable ICMP sweeps; `ping` = single-host checks.  
- `nmap` host-discovery flags (`-PE`, `-PS`, `-PA`, `-PU`, `-PR`) let you adapt to filtering.  
- When in doubt, **combine methods** to reduce false negatives.

# eJPT Study Guide 

## Port Scanning

