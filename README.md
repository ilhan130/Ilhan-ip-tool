# 🌐 Ilhan IP Tool – Installation Guide

A professional IP information lookup tool for Termux with detailed network insights.

---

## 📋 Prerequisites

| Requirement | Details |
|-------------|---------|
| **Device**  | Android 7.0 or higher |
| **Termux**  | Latest version from F-Droid |
| **Storage** | ~50 MB free space |
| **Network** | Active internet connection |

---

## 🚀 Quick Installation Script

Copy and paste this single command to install everything automatically:

```bash
pkg update -y && pkg upgrade -y && pkg install git -y && git clone https://github.com/ilhan130/Ilhan-ip-tool.git && cd Ilhan-ip-tool && chmod +x ilhaniptool.sh && ln -s $PWD/ilhaniptool.sh $PREFIX/bin/ilhanip && echo "✅ Installation complete! Run with: ilhanip"





## ‼️‼️Quick update to new Script



cd ~/Ilhan-ip-tool
git pull
chmod +x ilhaniptool.sh
