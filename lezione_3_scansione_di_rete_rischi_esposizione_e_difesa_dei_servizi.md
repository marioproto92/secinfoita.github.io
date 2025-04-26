**Lezione 3**

È fondamentale comprendere i rischi associati all'esposizione diretta di dispositivi e servizi su Internet, specialmente quando non sono adeguatamente protetti. Una pratica comune per valutare questi rischi è l'analisi delle reti, talvolta effettuata attraverso strumenti automatizzati. Prendiamo ad esempio un set di script Python che ho creato per questo scopo: il suo obiettivo è scandagliare range di indirizzi IP, identificando servizi attivi e tentando di correlarli a vulnerabilità note. Questo tipo di analisi può essere focalizzato, ad esempio, su blocchi di indirizzi IP italiani, magari all'interno di un ampio range CIDR come un /8, con un interesse specifico per determinati provider come Vodafone, per comprendere l'esposizione in un contesto geografico o di rete specifico.

Il funzionamento di uno script del genere può essere illustrato esaminando direttamente il codice. Lo script principale, `vulnscanner_direct.py`, inizia importando le librerie necessarie (come `socket`, `threading`, `queue`) e definendo la configurazione della scansione:

```python
# Configurazione
TARGET_COUNTRY_CODE = "IT"      # Cambia il country code (Attualmente commentato nel codice)
THREADS = 100                   # Thread concorrenti
PORTS = [22, 80, 443, 21, 3389] # Porte da scansionare
IP_RANGE = "37.179.0.0/16"      # Range IP da scansionare
CSV_FILENAME = "risultati_scansione.csv" # Nome file CSV output
ip_queue = queue.Queue()
```

Questo definisce le porte target (SSH, HTTP, HTTPS, FTP, RDP), il numero di processi paralleli (thread) per accelerare il lavoro, il range IP in notazione CIDR da cui generare gli indirizzi, e il nome del file per salvare i risultati. Viene inizializzata una coda (`ip_queue`) per gestire gli IP da distribuire ai thread. Lo script include funzioni per preparare il file CSV (`setup_csv`) e salvare i risultati (`salva_risultato_csv`):

```python
def setup_csv(filename):
    if not os.path.exists(filename):
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['IP', 'Porta', 'Banner', 'CVE', 'Descrizione'])

def salva_risultato_csv(ip, port, banner, cve_info):
    with open(CSV_FILENAME, 'a', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        if cve_info:
            # Assume cve_info sia una tupla/lista con (ID, Descrizione)
            cve_id, description = cve_info
        else:
            cve_id, description = "N/A", "N/A"
        writer.writerow([ip, port, banner.strip(), cve_id, description])
```

La generazione degli IP avviene tramite la funzione `generate_ips_from_cidr`. Il cuore della scansione per singolo IP e porta è la funzione `grab_banner`:

```python
def grab_banner(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((ip, port))
        # Invia una semplice richiesta HTTP HEAD per stimolare una risposta
        sock.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()
        return banner
    except:
        # In caso di errore (timeout, connessione rifiutata, ecc.) non ritorna nulla
        return None
```

Questa funzione tenta di connettersi, invia una richiesta basilare per ottenere una risposta (il "banner") e la restituisce. L'uso di `try...except` e `decode(errors='ignore')` gestisce potenziali problemi di connessione o dati non testuali.

La logica eseguita da ogni thread è contenuta nella funzione `scanner`:

```python
def scanner():
    while not ip_queue.empty():
        ip = ip_queue.get()
        try:
            # (Logica di controllo paese commentata nel codice originale)
            print(f"[+] IP Valido ({TARGET_COUNTRY_CODE}): {ip}") # Stampa l'IP in analisi
            for port in PORTS:
                banner = grab_banner(ip, port)
                if banner:
                    print(f"    [*] {ip}:{port} - Banner: {banner}")
                    # Chiama il motore di matching per trovare CVE
                    cve_info = match_banner_to_cve(banner)
                    if cve_info:
                        print(f"    [!!!] VULNERABILITA' TROVATA: {cve_info}")
                    # Salva sempre il risultato se un banner è stato trovato
                    salva_risultato_csv(ip, port, banner, cve_info)
        except Exception as e:
            # Gestione errori minimale
            pass
        finally:
            # Segnala che l'attività per questo IP è completata
            ip_queue.task_done()
```

Questo loop preleva un IP dalla coda, itera sulle porte configurate, chiama `grab_banner`, e se ottiene un banner, lo stampa, lo passa al motore di matching (`match_banner_to_cve`) e salva il risultato.

Il matching avviene tramite il modulo `matcher_engine.py`:

```python
# matcher_engine.py
from cve_db import CVE_DATABASE

def match_banner_to_cve(banner):
    # Itera sul database delle firme CVE
    for signature, cve_info in CVE_DATABASE.items():
        # Se la firma è contenuta nel banner...
        if signature in banner:
            # ...restituisce le informazioni sulla CVE
            return cve_info # Assume cve_info sia (ID, Descrizione)
    # Nessuna corrispondenza trovata
    return None
```

Questa funzione riceve il banner e lo confronta con le chiavi (firme) di un dizionario `CVE_DATABASE` definito in `cve_db.py`. Il database fornito è molto semplice:

```python
# cve_db.py
CVE_DATABASE = {
    "Apache/2.4.49": ("CVE-2021-41773", "Apache Path Traversal RCE"),
    "OpenSSH_7.2p2": ("CVE-2016-0777", "SSH information leak"),
    "Microsoft-IIS/7.5": ("CVE-2015-1635", "HTTP.sys Remote Code Execution"),
    "ProFTPD 1.3.5": ("CVE-2015-3306", "ProFTPD mod_copy arbitrary file access"),
}
```

Se una firma è presente nel banner, la funzione restituisce la tupla (ID CVE, Descrizione) associata. L'orchestrazione finale avviene nella funzione `main` di `vulnscanner_direct.py`, che inizializza il CSV, popola la coda con gli IP generati e mescolati, avvia i thread e attende il completamento della scansione.

Pur illustrando i concetti base di uno scanner, questo codice ha limiti significativi: il matching è rudimentale, il database CVE è statico e minuscolo, la cattura del banner è inefficace per molti protocolli e non tiene conto del contesto o delle patch di sistema (backporting).

Analisi approfondite e valutazioni sul campo, condotte su servizi identificati tramite banner simili, offrono uno spaccato più realistico dei pericoli. Un dato allarmante che emerge frequentemente è la presenza diffusa di software obsoleto, non più supportato dai produttori (End-of-Life, EoL). Si scoprono spesso versioni datate di sistemi operativi embedded, server web minimali come Boa, vecchie release di Nginx, stack web con componenti come Apache 2.4.6 accoppiato a OpenSSL 1.0.2k e PHP 5.4.16, o versioni di OpenSSH come la 5.8, rilasciate molti anni fa. Questi sistemi, non ricevendo più aggiornamenti, accumulano vulnerabilità note, diventando facili bersagli.

Inoltre, le analisi confermano la difficoltà nell'interpretare banner generici (come "Caddy", "nginx", "web", "Webs", "SHIP 2.0", "Sky"). Questi forniscono poche informazioni utili, rendendo necessaria un'indagine più approfondita con tecniche avanzate per identificare il software reale e il suo contesto. Le valutazioni per questi banner sono spesso condizionali, basate sull'interpretazione più probabile (es., "Webs" potrebbe indicare il server GoAhead), evidenziando l'incertezza intrinseca della sola analisi del banner.

Al di là dell'obsolescenza, le valutazioni associano spesso banner specifici a vulnerabilità concrete e potenzialmente gravi: Esecuzione di Codice Remoto (RCE), Denial of Service (DoS), divulgazione di informazioni, SQL Injection, Path Traversal. Queste possono affliggere versioni specifiche di sistemi operativi, server web, librerie crittografiche, linguaggi di programmazione e persino plugin di terze parti o firmware di dispositivi. Anche versioni di software che potrebbero sembrare sicure rispetto a una minaccia recente possono rimanere vulnerabili a problemi più vecchi ma ancora sfruttabili. Le analisi evidenziano anche limiti importanti, come l'impossibilità, basandosi solo sul banner, di verificare le patch specifiche (backporting) applicate dalle distribuzioni Linux, che potrebbero rendere sicuro un servizio apparentemente vulnerabile.

Tutto ciò converge sui gravi rischi derivanti dall'esposizione non protetta di dispositivi e servizi su Internet. Apre le porte ad accessi non autorizzati, furto di dati, attacchi ransomware, interruzioni di servizio (DoS), e alla compromissione dell'infrastruttura, che può essere usata per lanciare ulteriori attacchi. Un incidente di sicurezza può inoltre causare danni reputazionali significativi.

È cruciale ricordare sempre le implicazioni etiche e legali: eseguire scansioni su reti altrui senza esplicita autorizzazione è illegale. Qualsiasi strumento o analisi di questo tipo deve essere utilizzato solo a scopo educativo o per audit autorizzati sui propri sistemi.

Fortunatamente, esistono strategie efficaci per mitigare questi rischi. La regola fondamentale è ridurre la superficie d'attacco, esponendo solo i servizi indispensabili e utilizzando metodi di accesso sicuro come le VPN anziché aprire porte direttamente su Internet. Un rigoroso processo di patch management è essenziale per mantenere aggiornati sistemi operativi, applicazioni, librerie e firmware. L'implementazione di firewall robusti e la segmentazione della rete aiutano a contenere eventuali incidenti. È altrettanto importante l'"hardening", ovvero la configurazione sicura dei servizi, disabilitando funzionalità non necessarie e seguendo le best practice. Il monitoraggio costante, l'uso di password forti con autenticazione multi-fattore (MFA) e l'esecuzione periodica di vulnerability assessment (con strumenti professionali e autorizzazione) completano un approccio difensivo solido.

In conclusione, la sicurezza informatica richiede un impegno costante e proattivo. L'esposizione non protetta di servizi è un rischio troppo grande per essere ignorato, come dimostrano le analisi sul campo. Affidarsi a banner ambigui o a una sicurezza "per oscurità" è inefficace. Solo attraverso una combinazione di patching diligente, configurazioni sicure, limitazione dell'esposizione e monitoraggio continuo è possibile proteggere adeguatamente le risorse digitali nel complesso ecosistema interconnesso di oggi.
