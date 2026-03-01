# WordPress Security Benchmark 🛡️

**A Comprehensive Full-Stack Hardening Guide for Enterprise WordPress Environments.**

[![License: CC BY-SA 4.0](https://img.shields.io/badge/License-CC%20BY--SA%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-sa/4.0/)
[![WordPress Version](https://img.shields.io/badge/WordPress-6.x-blue.svg)](https://wordpress.org)
[![PHP Version](https://img.shields.io/badge/PHP-8.2%2B-777bb4.svg)](https://www.php.net/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20(Ubuntu/Debian)-lightgrey.svg)](https://ubuntu.com/)

---

## 📖 Overview

The **WordPress Security Benchmark** provides prescriptive, actionable guidance for establishing a secure configuration posture for WordPress 6.x running on a modern Linux server stack. This guide covers the entire stack to address hardening at the OS, Web Server, PHP, and Database layers.

### Key Focus Areas:
- 🛡️ **Web Server Hardening** (Nginx & Apache)
- ⚙️ **PHP Runtime Security**
- 🗄️ **Database Isolation & Least Privilege** (MySQL & MariaDB)
- 🔑 **WordPress Core Configuration**
- 🔒 **Authentication & Access Control** (2FA, session management, least privilege)
- 📁 **File System Permissions**
- 📊 **Logging, Monitoring & Malware Detection**
- 📦 **Supply Chain & Extension Management** (SBOM, plugin vetting)
- 🌐 **WAF, Backup & Recovery**
- 🤖 **AI & Generative AI Security**
- 🖧 **Server Access & Network** (SSH, SFTP, firewall, process isolation)
- 🏗️ **Multisite Security**

---

## 🥞 Target Technology Stack

This benchmark is optimized for the following environment:

| Component | Minimum Version | Recommended |
| :--- | :--- | :--- |
| **WordPress** | 6.x | Latest Stable |
| **OS** | Ubuntu 22.04+ / Debian 12+ | Latest LTS |
| **PHP** | 8.2+ | 8.3+ |
| **Web Server** | Nginx 1.24+ / Apache 2.4+ | Latest |
| **Database** | MySQL 8.0+ / MariaDB 10.6+ | Latest |

---

## 🧀 Security Profile Definitions

The benchmark categorizes recommendations into two levels of security posture:

### **Level 1: Essential Hardening**
Foundational security settings that can be implemented on any WordPress deployment with minimal impact on functionality. **Every site should meet this baseline.**

### **Level 2: Defense-in-Depth**
Strict security controls intended for high-risk environments handling sensitive data or regulated content. These may require additional operational overhead or custom tooling.

---

## 📂 Project Structure

- **[WordPress-Security-Benchmark.md](WordPress-Security-Benchmark.md)**: The full technical guide containing detailed audits and remediation steps.
- **[WordPress-Security-Benchmark.docx](WordPress-Security-Benchmark.docx)**: A Microsoft Word .docx version formatted as a template to generate the PDF.
- **[WordPress-Security-Benchmark.pdf](WordPress-Security-Benchmark.pdf)**: The PDF version of the guide. (Will make it prettier in the future.)

---

## 👩🏾‍💻 Usage

This guide is intended for:
- **System Administrators** & **DevOps Engineers**
- **Security Engineers**
- **WordPress Developers**

Each recommendation includes:
1. **Description**: Clear explanation of the setting.
2. **Rationale**: Why this setting is critical for security.
3. **Audit**: Commands to verify compliance on your server.
4. **Remediation**: Step-by-step instructions to apply the fix.

---

## 📒 Related Reading

- [WordPress Security Architecture and Hardening Guide](https://github.com/dknauss/wp-security-hardening-guide): Enterprise-focused security architecture and hardening guide covering threat landscape, OWASP Top 10 coverage, server hardening, authentication, supply chain, incident response, and AI security.

- [Securing WordPress](https://cio.ubc.ca/information-security/policy-standards-resources/M5/gui-securing-wordpress): Information Security Guideline from the University of British Columbia's Office of the CIO.

- [Hardening WordPress](https://developer.wordpress.org/advanced-administration/security/): Official WordPress.org developer documentation, The  Advanced Administration Handbook. Note the useful "[Hardening WordPress](https://developer.wordpress.org/advanced-administration/security/hardening/)" Security subsection. 

- [WordPress Security Style Guide](https://github.com/dknauss/wp-security-style-guide): Principles and terminology for writing about WordPress security effectively.

## 🤝 Contributing

Contributions are welcome! If you find an error or have an improvement for the benchmark, please open an issue or submit a pull request.

---

## 📄 License

This project is licensed under the [Creative Commons Attribution-ShareAlike 4.0 International License (CC BY-SA 4.0)](https://creativecommons.org/licenses/by-sa/4.0/).

---

*Created by Dan Knauss • February 2026*
