# Breaking-In-Study-Guide-for-INE-s-Junior-Penetration-Tester-Certification
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
- **HTTrack** → Downloads an entire website for offline analysis.  

---

### 📚 Key Takeaways  
- Website recon maps out the **public-facing attack surface**.  
- DNS analysis can expose valuable subdomains and infrastructure details.  
- Check `robots.txt` and `sitemap.xml` for hidden directories and content.  
- Use both **browser add-ons** and **CLI tools** to gather tech stack details.  


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


