
---

📥 Installation Guide – Ilhan IP Tool

This guide explains how to install and run Ilhan IP Tool on Termux easily.


---

📱 Requirements

Android device

Termux (latest version)

Internet connection



---

🔄 Step 1: Update Termux

pkg update && pkg upgrade -y


---

📦 Step 2: Install Required Package

pkg install git -y


---

📥 Step 3: Clone the Repository

git clone https://github.com/ilhan130/Ilhan-ip-tool.git


---

📂 Step 4: Enter Tool Directory

cd Ilhan-ip-tool


---

🔐 Step 5: Give Execute Permission

chmod +x ilhaniptool.sh


---

⚙️ Step 6: Create Default Command (Run Anytime)

This will allow you to run the tool using ilhanip from anywhere in Termux.

ln -s $PWD/ilhaniptool.sh $PREFIX/bin/ilhanip


---

▶️ Step 7: Run the Tool

ilhanip

or directly:

./ilhaniptool.sh


---

🛠 Features

🌐 Find your own IP details

🔍 Lookup any public IP address

📊 20+ IP information fields

⚡ Fast & lightweight

📱 Optimized for Termux

❌ Exit anytime using CTRL + C



---

👨‍💻 Author

Ilhan PK

GitHub: https://github.com/ilhan130

Instagram: https://instagram.com/ilhan.pk

