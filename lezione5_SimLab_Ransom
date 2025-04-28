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

Ho progettato e realizzato **SimLab Framework v2** come strumento avanzato di simulazione ransomware, pensato per riflettere metodologie reali in modo sicuro e controllato.  
L’integrazione di tecniche polimorfiche e stealth garantisce che i test di detection e risposta siano estremamente vicini agli scenari reali moderni.
