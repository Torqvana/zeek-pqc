# Zeek PQC Discovery & Logging

This Zeek package provides visibility into the adoption of **Post-Quantum Cryptography (PQC)** within your network traffic. It monitors TLS (SSL) and SSH handshakes to identify the use or offer of quantum-resistant algorithms.

## Features

The script performs two main actions to assist with PQC transition monitoring:

### 1. Core Log Extension
The script extends standard Zeek logs to provide an immediate indicator of PQC usage in established sessions:
* **`ssl.log`**: Adds a boolean field `is_pqc`. It is set to `T` if the negotiated key share uses a PQC or Hybrid algorithm.
* **`ssh.log`**: Adds a boolean field `is_pqc`. It is set to `T` if the negotiated Key Exchange (KEX) algorithm is PQC or Hybrid.

### 2. PQC Discovery Log (`pqc.log`)
A dedicated log file, `pqc.log`, is generated to track the **capability** of hosts on your network. This log captures instances where a client or server advertises support for PQC, even if a classical algorithm is eventually chosen for the session

#### Log Fields (Pqc::Info)
| Field | Type | Description |
| :--- | :--- | :--- |
| `uid` | `string` | Unique identifier of the connection. |
| `host` | `addr` | The IP address of the host advertising PQC. |
| `is_client` | `bool` | `T` if the host is the client, `F` if it is the server. |
| `is_hybrid` | `bool` | `T` if the algorithm is a Hybrid (Classical + PQC) approach. |
| `service` | `string` | The protocol detected (`ssl` or `ssh`). |
| `pqc_algs` | `vector[string]` | List of PQC algorithms offered by the host. |

---

## Supported Algorithms

The script identifies the following algorithms based on current protocol drafts and standards:

### TLS (SSL)
* **Pure PQC**: ML-KEM-512, ML-KEM-768, ML-KEM-1024.
* **Hybrid**: 
    * SecP256r1/X25519 combined with ML-KEM768.
    * SecP384r1 combined with ML-KEM1024.
    * Legacy Kyber Drafts (X25519/SecP256r1).

### SSH
* **Pure PQC**: ML-KEM-1024-nistp384, ML-KEM-768-nistp256.
* **Hybrid**: sntrup761x25519 and ML-KEM768x25519.

---

## Installation

### Using zkg
Install this package via the Zeek Package Manager:
```bash
zkg install <your-github-repo-url>
