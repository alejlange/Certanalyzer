# Certanalyzer PKI Toolkit

A modern, multi-tab GUI Toolkit for PKI, SSL/TLS certificate analysis, and local keystore management. Designed specifically for Windows Server Administrators.

> *“Because if you have Linux, you just run OpenSSL. But on Windows, you need Certanalyzer.”* 😉

![Certanalyzer Screenshot](link_a_una_imagen_de_tu_app_aqui.png)

## Features

* **Network Analysis:** Enter an IP/Hostname and Port to fetch, validate, and diagnose the entire SSL/TLS certificate chain.
* **PKI Diagnostics:** Detects expired certs, broken chains, untrusted Root CAs, and missing intermediate certificates.
* **Local Keystore Matching:** Load `.cer`, `.pem`, or `.p12` files alongside a `.key` to mathematically verify if the public and private keys match.
* **PKI Toolkit (File Manipulation):**
  * **Concatenate:** Merge certificates and keys into a single CA-Bundle.
  * **Split:** Extract individual certificates from a multi-block PEM file.
  * **Convert:** Easily swap between PEM (Base64) and DER (Binary) formats.
  * **P12 Generator:** Pack a private key and certificates into a secure PKCS#12 (`.pfx`/`.p12`) vault ready for Windows/IIS deployment.
* **Export:** Download fetched network chains directly to your hard drive.

## Download & Run (For Users)

You don't need Python installed to run this app.
1. Go to the [Releases page](../../releases/latest).
2. Download the latest `Certanalyzer.exe`.
3. Run it directly (Portable app, no installation required).

## Build from Source (For Developers)

If you want to run the python script directly or build it yourself:

1. Clone the repository:
   ```bash
   git clone [https://github.com/alejlange/Certanalyzer.git](https://github.com/alejlange/Certanalyzer.git)
   cd Certanalyzer


<img width="1136" height="1013" alt="image" src="https://github.com/user-attachments/assets/9e343844-66e9-4a47-b4d0-d9fc9330298b" />
