# WordPress Security Benchmark 🛡️

**A Comprehensive Full-Stack Hardening Guide for Enterprise WordPress Environments.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![WordPress Version](https://img.shields.io/badge/WordPress-6.x-blue.svg)](https://wordpress.org)
[![PHP Version](https://img.shields.io/badge/PHP-8.2%2B-777bb4.svg)](https://www.php.net/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20(Ubuntu/Debian)-lightgrey.svg)](https://ubuntu.com/)

---

## 📖 Overview

The **WordPress Security Benchmark** provides prescriptive, actionable guidance for establishing a secure configuration posture for WordPress 6.x running on a modern Linux server stack. 

This guide covers the **entire stack**, moving beyond simple plugin-based security to address hardening at the OS, Web Server, PHP, and Database layers.

### Key Focus Areas:
- 🛡️ **Web Server Hardening** (Nginx & Apache)
- ⚙️ **PHP Runtime Security**
- 🗄️ **Database Isolation & Least Privilege** (MySQL & MariaDB)
- 🧩 **WordPress Core Configuration**
- 📡 **Network & Firewall Policy**

---

## 🚀 Target Technology Stack

This benchmark is optimized for the following environment:

| Component | Minimum Version | Recommended |
| :--- | :--- | :--- |
| **WordPress** | 6.x | Latest Stable |
| **OS** | Ubuntu 22.04+ / Debian 12+ | Latest LTS |
| **PHP** | 8.2+ | 8.3+ |
| **Web Server** | Nginx 1.24+ / Apache 2.4+ | Latest |
| **Database** | MySQL 8.0+ / MariaDB 10.6+ | Latest |

---

## 🏗️ Security Profile Definitions

The benchmark categorizes recommendations into two levels of security posture:

### **Level 1: Essential Hardening**
Foundational security settings that can be implemented on any WordPress deployment with minimal impact on functionality. **Every site should meet this baseline.**

### **Level 2: Defense-in-Depth**
Strict security controls intended for high-risk environments handling sensitive data or regulated content. These may require additional operational overhead or custom tooling.

---

## 📂 Project Structure

- **[WordPress-Security-Benchmark.md](WordPress-Security-Benchmark.md)**: The full technical guide containing detailed audits and remediation steps.

---

## 🛠️ Usage

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

## 🤝 Contributing

Contributions are welcome! If you find an error or have an improvement for the benchmark, please open an issue or submit a pull request.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details (if applicable).

---

*Created by Dan Knauss • February 2026*
