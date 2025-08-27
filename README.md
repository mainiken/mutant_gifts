# Mutant Gifts Bot

[🇷🇺 Russian](README_RU.md) | [🇬🇧 English](README.md)

[<img src="https://res.cloudinary.com/dkgz59pmw/image/upload/v1736756459/knpk224-28px-channel_psjoqn.svg" alt="Channel Link" width="200">](https://t.me/+vpXdTJ_S3mo0ZjIy)
[<img src="https://res.cloudinary.com/dkgz59pmw/image/upload/v1736756459/knpk224-28px-chat_ixoikd.svg" alt="Chat Link" width="200">](https://t.me/+wWQuct9bljQ0ZDA6)

---

## 📑 Table of Contents
1. [Description](#description)
2. [Key Features](#key-features)
3. [Installation](#installation)
   - [Quick Start](#quick-start)
   - [Manual Installation](#manual-installation)
4. [Settings](#settings)
   - [Environment (.env) options](#environment-env-options)
5. [Support and Donations](#support-and-donations)
6. [Contact](#contact)

---

## 📜 Description
**Mutant Gifts Bot** is an automated bot for the
[@mutant_gifts_bot](https://t.me/mutant_gifts_bot?start=_tgr_uI1FOb9iODEy)
game. It supports multithreading, proxy integration, and automatic game
management.

---

## 🌟 Key Features
- 🔄 **Multithreading** — ability to work with multiple accounts in parallel
- 🔐 **Proxy Support** — secure operation through proxy servers
- 🎯 **Quest Management** — automatic quest completion
- 📊 **Statistics** — detailed session statistics tracking

---

## 🛠️ Installation

### Quick Start
1. **Download the project:**
   ```bash
   git clone https://github.com/mainiken/mutant_gifts.git
   cd mutant_gifts
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure parameters in the `.env` file:**
   ```bash
   API_ID=your_api_id
   API_HASH=your_api_hash
   ```

### Manual Installation
1. **Linux:**
   ```bash
   sudo sh install.sh
   python3 -m venv venv
   source venv/bin/activate
   pip3 install -r requirements.txt
   cp .env-example .env
   nano .env  # Enter your API_ID and API_HASH
   python3 main.py
   ```

2. **Windows:**
   ```bash
   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   copy .env-example .env
   python main.py
   ```

---

## ⚙️ Settings

| Parameter                  | Default Value         | Description                                                 |
|---------------------------|----------------------|-------------------------------------------------------------|
| **API_ID**                |                      | Telegram API application ID                                 |
| **API_HASH**              |                      | Telegram API application hash                               |
| **GLOBAL_CONFIG_PATH**    |                      | Path for configuration files. By default, uses the TG_FARM environment variable |
| **FIX_CERT**              | False                | Fix SSL certificate errors                                  |
| **SESSION_START_DELAY**   | 360                  | Delay before starting the session (seconds)                 |
| **REF_ID**                |                      | Referral ID for new accounts                                |
| **USE_PROXY**             | True                 | Use proxy                                                   |
| **SESSIONS_PER_PROXY**    | 1                    | Number of sessions per proxy                                |
| **DISABLE_PROXY_REPLACE** | False                | Disable proxy replacement on errors                         |
| **BLACKLISTED_SESSIONS**  | ""                   | Sessions that will not be used (comma-separated)            |
| **DEBUG_LOGGING**         | False                | Enable detailed logging                                     |
| **DEVICE_PARAMS**         | False                | Use custom device parameters                                |
| **AUTO_UPDATE**           | True                 | Automatic updates                                           |
| **CHECK_UPDATE_INTERVAL** | 300                  | Update check interval (seconds)                             |

### Environment (.env) options

Copy `.env-example` to `.env` and adjust as needed. Key automation
options from `.env-example`:

```ini
# Telegram API
API_ID = 
API_HASH = 
GLOBAL_CONFIG_PATH = 

# SSL
FIX_CERT = True

# Session behavior
SESSION_START_DELAY = 360
REF_ID = 'r_252453226'
SESSIONS_PER_PROXY = 1
USE_PROXY = True
DISABLE_PROXY_REPLACE = False

# Device and logging
DEVICE_PARAMS = False
DEBUG_LOGGING = False

# Updates
AUTO_UPDATE = True
CHECK_UPDATE_INTERVAL = 300
BLACKLISTED_SESSIONS = ""

# Mutant Gifts automation
AUTO_MUTATION = True
AUTO_BATTLE = True
AUTO_UPGRADE = True
MIN_COINS_BALANCE = 
```

Descriptions:
- **AUTO_MUTATION**: enable automatic mutation actions
- **AUTO_BATTLE**: enable automatic battle actions
- **AUTO_UPGRADE**: enable automatic upgrades
- **MIN_COINS_BALANCE**: minimal coin balance to keep before spending

---

## 💰 Support and Donations

Support the development:

| Currency      | Address |
|---------------|---------|
| **Bitcoin**   | `bc1pfuhstqcwwzmx4y9jx227vxcamldyx233tuwjy639fyspdrug9jjqer6aqe` |
| **Ethereum**  | `0x9c7ee1199f3fe431e45d9b1ea26c136bd79d8b54` |
| **TON**       | `UQBpZGp55xrezubdsUwuhLFvyqy6gldeo-h22OkDk006e1CL` |
| **BNB**       | `0x9c7ee1199f3fe431e45d9b1ea26c136bd79d8b54` |
| **Solana**    | `HXjHPdJXyyddd7KAVrmDg4o8pRL8duVRMCJJF2xU8JbK` |

---

## 📞 Contact

If you have questions or suggestions:
- **Telegram**: [Join our channel](https://t.me/+vpXdTJ_S3mo0ZjIy)

---
## ⚠️ Disclaimer

This software is provided "as is" without any warranties. By using this bot, you accept full responsibility for its use and any consequences that may arise.

The author is not responsible for:
- Any direct or indirect damages related to the use of the bot
- Possible violations of third-party service terms of use
- Account blocking or access restrictions

Use the bot at your own risk and in compliance with applicable laws and third-party service terms of use.
