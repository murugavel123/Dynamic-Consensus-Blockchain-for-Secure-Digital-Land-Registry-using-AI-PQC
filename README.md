
# Dynamic-Consensus-Blockchain-for-Secure-Digital-Land-Registry-using-AI-PQC

Welcome to this **next-generation digital land registry platform** — a secure, adaptive, and community-governed system built on blockchain technology.

This project simulates how land ownership can be recorded, verified, and transferred using modern techniques such as:

* **Machine learning to dynamically choose consensus methods**
* **Post-quantum cryptography for future-proof digital signatures**
* **Decentralized governance where peers approve new users**
* **Tamper-proof, immutable records of land transactions**

This combination of technologies makes the system **secure, transparent, resilient, and adaptable to changing network conditions**.

---

## What It Does

Traditional land registry systems are often slow, paper-based, and vulnerable to tampering or fraud. This project demonstrates an innovative approach by:

* Letting users upload land deed PDFs where the system computes a **secure hash** for verification.
* Recording ownership transfers as **blockchain transactions**.
* Using **Post-Quantum Cryptographic (PQC) signatures** to make records safe even against future quantum attacks.
* Employing an **ML model** to predict the most efficient consensus protocol (like PoW, PoS, PBFT, Raft, or HotStuff) based on current network behavior and load.
* Including a **peer-review system** where existing users vote to approve or reject new participants.

This makes the platform suitable as a **proof-of-concept for modern, secure, and decentralized land records** that governments, municipalities, or smart cities could adopt.

---

## Features At a Glance

* Adaptive consensus selection using real-time AI
* Post-quantum digital signatures for transaction integrity
* Multi-node blockchain simulator
* Decentralized user approval and governance
* Persistent state saving and recovery
* Land transaction queuing and live ledger display

---

## Why It Matters

By blending **AI with blockchain and advanced cryptographic techniques**, this project goes beyond static systems. It simulates a world where:

* The blockchain adapts intelligently to conditions
* Security remains strong even in a post-quantum era
* Users collectively govern system access
* Land ownership becomes transparent and tamper-resistant

This isn’t just code — it’s a **vision for future digital infrastructure**.

---

## Tech Stack

* **Python & Flask** — backend and web server
* **Machine Learning** — dynamic consensus prediction
* **Post-Quantum Cryptography (PQC)** — secure signature generation
* **JSON + CSV** — persistent storage
* **Tailwind CSS + HTML** — clean user interface

---

## Getting Started

1. **Clone this repository**

   ```bash
   git clone https://github.com/murugavel123/Dynamic-Consensus-Blockchain-for-Secure-Digital-Land-Registry-using-AI-PQC
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

   (Flask, pandas, numpy, joblib, quantcrypt, werkzeug)

3. **Run the app**

   ```bash
   python app.py
   ```

4. **Open your browser**

   ```
   http://localhost:5000
   ```

---

## How It Works

1. **Users sign up/login** — accounts can be approved by community voting.
2. **Land transactions are submitted** with PDF documents.
3. **System hashes and signs the document** using post-quantum cryptography.
4. **ML predicts optimal consensus protocol** to validate the transaction.
5. **Blockchain adds the transaction to the ledger** and displays it on the dashboard.
6. **Governance and consensus interface** shows live nodes and transaction queue.

---

## Governance & Community

Instead of a central administrator, this platform uses a **peer-review governance model** where existing participants:

* Vote to approve new users
* Participate in consensus decisions
* Help maintain network integrity

This reflects real decentralized decision-making.

---

## Use Cases

* Proof of concept for **government land registries**
* Testing **adaptive consensus algorithms**
* Research on **blockchain + AI + PQC integration**
* Learning platform for **decentralized systems architecture**

---

## License

This project is open-source and free to use under the [MIT License](LICENSE).

---
