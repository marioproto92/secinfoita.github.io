# Printer Job Language (PJL) nei file di aggiornamento firmware

La **Printer Job Language (PJL)** è un linguaggio di controllo sviluppato da HP per gestire comandi a livello di job di stampa, consentendo di cambiare lingua di stampa (PCL, PostScript, ecc.), separare i job e leggere/scrivere parametri di dispositivo ([Printer Job Language - Wikipedia](https://en.wikipedia.org/wiki/Printer_Job_Language#:~:text=Printer%20Job%20Language%20,attendance%20and%20file%20system%20commands)). Tipicamente ogni job PJL inizia e termina con la sequenza **Universal Exit Language (UEL)** `<ESC>%-12345X`, che resetta la stampante e passa ai comandi PJL. Ad esempio, un’intestazione PJL tipica inizia così: 

``` 
<ESC>%-12345X 
@PJL JOB NAME="Example" 
@PJL SET STRINGCODESET=UTF8 
@PJL ENTER LANGUAGE=PCL 
... 
<ESC>%-12345X 
``` 

dove `<ESC>` è il carattere 0x1B, `@PJL` introduce i comandi PJL (che usano parola chiave e parametri), e infine si chiama una lingua di stampa (ad es. PCL) con `@PJL ENTER LANGUAGE=...`. Tra i comandi principali si ricordano **@PJL SET** (per impostare variabili di job o di stampante, es. codifica caratteri, quantità copie, impostazioni periferiche), **@PJL DEFAULT** (per ripristinare valori di default), **@PJL JOB/EOJ** (inizio/fine job), **@PJL INFO** (status), e comandi del file system *FS* (come FSUPLOAD, FSQUERY, FSDELETE) usati per accedere alla memoria della stampante ([Printer Job Language Technical Reference Manual - ENWW](https://developers.hp.com/sites/default/files/PJL_Technical_Reference_Manual.pdf#:~:text=FSUPLOAD%20Command%20The%20FSUPLOAD%20command,is%20valid%3A%20%40PJL%20FSUPLOAD%20FORMAT%3ABINARY)) ([Printer Job Language Technical Reference Manual - ENWW](https://developers.hp.com/sites/default/files/PJL_Technical_Reference_Manual.pdf#:~:text=~NAME%20%3D%20,FF)). Ad esempio, `@PJL FSUPLOAD NAME="0:\path\file" OFFSET=25 SIZE=512` chiede di trasferire 512 byte dal file interno “file”, a partire dal 25° byte ([Printer Job Language Technical Reference Manual - ENWW](https://developers.hp.com/sites/default/files/PJL_Technical_Reference_Manual.pdf#:~:text=FSUPLOAD%20Command%20The%20FSUPLOAD%20command,is%20valid%3A%20%40PJL%20FSUPLOAD%20FORMAT%3ABINARY)) ([Printer Job Language Technical Reference Manual - ENWW](https://developers.hp.com/sites/default/files/PJL_Technical_Reference_Manual.pdf#:~:text=~NAME%20%3D%20,FF)).

Un caso particolare è l’uso di PJL per l’**aggiornamento firmware**. Nei pacchetti firmware HP (formato RFU/.ful), si trova ad inizio file una sezione PJL con comandi `@PJL COMMENT` che riportano modello, versione e datacode, e persino una stringa di upgrade size (dimensione firmware). Subito dopo compare il comando di reset e il messaggio di errore “*This device does not support FWUPDATE!*” se la stampante non entra in modalità firmware. In particolare, il comando chiave è: 

``` 
@PJL ENTER LANGUAGE=FWUPDATE 
``` 

che istruisce la stampante a passare in una modalità speciale di aggiornamento firmware. Come nota **Costin (HP)**, il linguaggio `FWUPDATE` non è documentato pubblicamente ma serve esattamente per questo scopo: nel file FWUPDATE si trovano solo dati e comandi necessari per trasferire il firmware nella memoria interna. In sintesi, la struttura tipica è: 

- **UEL iniziale** `<ESC>%-12345X` per uscire da qualsiasi lingua e entrare in PJL.  
- `@PJL COMMENT` con informazioni (modello, versioni, ecc.).  
- Un comando proprietario (es. `UPGRADE SIZE=12345678`) che indica la dimensione del firmware (vedi note).  
- `@PJL ENTER LANGUAGE=FWUPDATE` per entrare in modalità di firmware update.  
- Eventuale reset macchina (`<ESC>E`) e messaggio di servizio come l’errore “FWUPDATE non supportato”.  
- **Blocchi di dati** (vedi sotto) codificati come se fossero comandi PCL raster tramite comandi *b*.  
- **UEL finale** `<ESC>%-12345X` a job finito.  

L’intero file *ful* è quindi progettato come un “lavoro di stampa” PJL che in realtà trasferisce un firmware invece di stampare una pagina. Ciò permette allo strumento di aggiornamento di comunicare il firmware anche su interfacce di stampa standard (USB, reti come LPR, ecc.). Ad esempio, un frammento iniziale reale estratto da un `.ful` HP OfficeJet Pro 8720 mostra: 

```
<ESC>%-12345X
@PJL COMMENT MODEL=HP OfficeJet Pro8720
@PJL COMMENT VERSION=WMP1CN1919BR
@PJL COMMENT DATECODE=20190510
@PJL UPGRADE SIZE=39640723
<ESC>%-12345X
@PJL COMMENT(NULL)
@PJL ENTER LANGUAGE=FWUPDATE
<ESC>EThis device does not support FWUPDATE!
\r\n
... (seguono i dati FWUPDATE) ...
<ESC>%-12345X
``` 

In questa sequenza si vede l’uso di UEL, commenti PJL, il comando non-dichiarato `UPGRADE SIZE`, e infine `ENTER LANGUAGE=FWUPDATE`. Questo conferma che per estrarre il firmware è necessario interpretare i successivi dati come un flusso PCL/FWUPDATE, non come testo normale. 

## Struttura dei dati binari e comandi *b* PCL

All’interno del flusso FWUPDATE, il firmware vero e proprio è codificato come una serie di **grafica raster PCL**. In pratica, il protocollo FWUPDATE usa i comandi PCL del tipo `ESC * b ...` (prefix `<ESC>*b`) per trasferire dati binari (considerati come immagini o blocchi di dati compressi). Questi comandi *b* sono definiti nel manuale PCL: per esempio `ESC * b # W [dati]` trasferisce un blocco di dati raster di lunghezza `#` bytes ([PCL 5 Printer Language Technical Reference Manual - ENWW](http://www.hp.com/ctg/Manual/bpl13210.pdf#:~:text=EN%20Transfer%20Raster%20Data%20Command,the%20left%20raster%20graphics%20margin)). In dettaglio:

- **`ESC * b # W`**: trasferisce `#` byte di dati binari come una riga di immagine. Il numero `#` viene messo subito dopo `*b` e prima della lettera `W`. Ad esempio, la definizione PCL dice: 

  > *Transfer Raster Data:* il comando `ESC *b#W[data]` invia # byte (`0–32767`) di dati bitwise che rappresentano una riga di stampa ([PCL 5 Printer Language Technical Reference Manual - ENWW](http://www.hp.com/ctg/Manual/bpl13210.pdf#:~:text=EN%20Transfer%20Raster%20Data%20Command,of%20raster%20graphics%20data%20that)).  

  Nel contesto FWUPDATE, i byte trasportati non sono pixel di un’immagine, ma semplicemente blocchi di firmware. Ad esempio, la sequenza `ESC*b2361W` significa “trasferisci 2361 byte di dati grezzi immediatamente dopo questo comando”. Tali byte vengono raccolti dallo script come porzione di firmware.  

- **`ESC * b # V`**: trasferisce dati “per piano” (utile per immagini a più canali). Qui `#` indica quanti byte seguono. Nel caso di firmware spesso si usa piano singolo o nessun piano particolare. Nella decompilazione citata si vede che `ESC*b#V` viene usato con un metodo di compressione (vedi sotto).  

- **`ESC * b # M`**: imposta il metodo di compressione per i comandi successivi. Ad esempio `ESC*b2M` significa “metodo di compressione = 2 (TIFF)”. Questo non trasferisce dati di per sé, ma indica come interpretare i dati raw (ad es. run-length, TIFF, ecc.).  

- **`ESC * b # Y`**: “Raster Y Offset”: sposta il cursore verticale di # righe senza trasferire dati. Viene usato per salto di righe bianche. Ad esempio `ESC*b+1Y` salta 1 riga.  

In pratica, **solo i comandi con suffisso `W` (o talvolta `V`) contengono dati binari significativi**. Gli altri (`M`, `Y`, ecc.) servono a controllare la modalità o la posizione nel flusso. Il PCL Reference Manual elenca così alcune sequenze *b*:  

``` 
ESC*b#M   (*Imposta il metodo di compressione*)  
ESC*b#V   (*Trasferisce dati raster per piano*)  
ESC*b#W   (*Trasferisce dati raster per riga/blocco*)  
ESC*b#Y   (*Raster Y Offset – salta righe*)  
```  

 ([*	Introduction	1-1](https://developers.hp.com/system/files/attachments/PCL%20Implementors%20Guide-23-Index%20by%20esc%20sequence.pdf#:~:text=Esc%2Ab%23M%20...............................................Compression%20Method.........................................................%2013,11%20Esc%2Ab%23X................................................X%20Offset)) 

Ad esempio, come spiega il manuale HP, il comando PCL `EC*b2m3W[data]` significa “imposta compressione=2 (TIFF) e trasferisci 3 byte di dati non compressi” ([PCL 5 Printer Language Technical Reference Manual - ENWW](http://www.hp.com/ctg/Manual/bpl13210.pdf#:~:text=Note%20The%20byte%20count%20of,that%203%20bytes%20of%20literal)). Nella decompilazione FWUPDATE si vede un caso analogo: `ESC*b2m14V` (metodo 2, decompressi 14 byte) seguito dai dati, terminato da `ESC*bW` come obbligatorio. 

Quindi, in breve: i **dati binari del firmware** sono spezzati in blocchi codificati come comandi PCL `*b...W` (o `*b...V`). Nel flusso si incontrano molte sequenze `<ESC>*b` sparse in tutto il file. I comandi `*bNNNNW` precedono vere e proprie sequenze di `NNNN` byte di payload; gli altri comandi `*bNNNNM/V/Y` servono solo a impostare parametri (compressione, offset) e non contengono dati di firmware. Ad esempio, l’analisi del file RFU HP mostra ripetutamente blocchi come `ESC*b16109V`, `ESC*b16306V`, `ESC*b2361W` ecc.: in genere i blocchi con `W` contengono porzioni di firmware che lo script Python ricostruirà (mentre `M/V/Y` sono ignorati come “chiavi di controllo”). 

## Script Python di estrazione del firmware

Lo **script Python** fornito si occupa di leggere il file `.ful` e di estrarre i blocchi di dati binari codificati con `*b...W` per ricostruire il firmware. In sintesi il funzionamento è: 

1. **Apertura file e lettura binaria**. Si apre il file `.ful` in modalità `rb` e si carica tutto il contenuto in memoria (ad esempio: `data = open('file.ful','rb').read()`).

2. **Ricerca dei comandi *b**. Lo script cerca tutte le occorrenze della sequenza di byte `<ESC>*b` all’interno del flusso dati. Questo può essere fatto con una funzione di ricerca (es. `data.find(b'\x1b*b', start)`) o con una regex Python (`re.finditer`). A ogni corrispondenza, si prende l’offset dell’inizio del comando.

3. **Parsing del comando *b**. Dall’offset trovato, lo script legge i caratteri successivi per interpretare il comando *b:  
   - Estrae il numero che segue `*b` (può avere segno `+` o `-`) fino alla lettera finale (`W`, `M`, `V`, `Y`). Ad esempio da `\x1b*b2361W` ricava `2361` e `W`. Da `\x1b*b+1ym4W` ricava `+1`, `y` (ossia `Y`) e capisce poi che seguono `m4W`.  
   - Converte il campo numerico in intero (ad es. `num = 2361`).  
   - Legge la lettera di tipo (`W`, `V`, `M` o `Y`) per stabilire il significato.  

4. **Calcolo offset e dimensione dati**. Se la lettera è **W** (trasferimento dati riga/blocco), allora `num` è il numero di byte di payload. Lo script calcola la posizione di inizio dati: tipicamente subito dopo il comando stesso. Per esempio, se il comando occupa *k* byte in totale, allora i dati utili sono `data[offset_cmd + k : offset_cmd + k + num]`. In molti script si tiene traccia del puntatore corrente: dopo aver trovato `ESC*b#W`, si avanza di `#` byte nel flusso. Se invece la lettera è `M`, `V` o `Y`, si salta al successivo *b senza estrarre dati (perché sono solo parametri o offset).  

5. **Estrazione del blocco**. Il blocco di dati di lunghezza `num` viene copiato in una lista o in un buffer di output. Ad esempio:  

   ```python
   if letter == 'W':
       start = match_end  # subito dopo ESC*b#W
       block = data[start : start + num]
       output_blocks.append(block)
       i = start + num     # salta i dati già letti
   else:
       i = match_end      # nessun dato da estrarre
   ```  

6. **Assemblaggio finale**. Alla fine della scansione, tutti i blocchi estratti (nell’ordine in cui appaiono) vengono concatenati. Questo produce un unico flusso binario corrispondente al firmware grezzo. Lo script quindi scrive questi dati su un file di output, ad esempio: `open('firmware_ricostruito.bin','wb').write(b''.join(output_blocks))`.

In pratica, lo script fa **una scansione riga per riga** del file `.ful`, trova ogni comando `ESC*b...W`, ne ricava il numero di byte `N` e copia i successivi `N` byte in sequenza. Gli offset *e* le dimensioni emergono automaticamente dall’analisi del testo: ad ogni comando *b*, lo script aggiorna la propria posizione nel flusso (`i`) e legge l’intervallo `[i, i+N)`. Le dimensioni dei blocchi sono date direttamente dal numero nel comando *b*, mentre l’offset nel firmware risultante è semplicemente la somma progressiva delle dimensioni precedenti (cioè, le porzioni vengono concatenate nell’ordine di lettura). 

**Esempio semplificato di estrazione** (pseudocodice): 

```python
data = open('update.ful','rb').read()
out = bytearray()
i = 0
while i < len(data):
    if data[i:i+3] == b'\x1b*b':   # trovato ESC * b
        # parse numero e lettera
        j = i+3
        sign = 1
        if data[j] == ord('+'): sign = +1; j+=1
        if data[j] == ord('-'): sign = -1; j+=1
        num = 0
        while data[j].isdigit():
            num = num*10 + (data[j]-48)
            j += 1
        num *= sign
        letter = chr(data[j]); j += 1
        # Se comando *b...W, estrai dati:
        if letter.upper() == 'W':
            block = data[j:j+num]
            out.extend(block)
            i = j + num
            continue
        else:
            # comando di controllo (M, Y, V): salta solo la parte letta finora
            i = j
            continue
    i += 1
open('firmware_ricostruito.bin','wb').write(out)
```

Alla fine si ottiene **il file firmware ricostruito**, identico all’originale immagine flash. L’uso di una regex per cercare `b'\x1b\\*b(\+?-?\d+)([MWYV])'` è una possibile alternativa, ma richiede attenzione ai casi come i segni `+` e a sequenze concatenate. In ogni caso, il principio è sempre quello: *individuare i comandi *b, calcolare quanti byte leggere, prelevare quei byte, e ripetere*.

**Riepilogo punti chiave**:
- I file PJL di aggiornamento firmware iniziano con UEL e commenti informativi, poi usano `@PJL ENTER LANGUAGE=FWUPDATE` per entrare in modalità firmware.  
- I dati binari del firmware sono trasportati tramite comandi PCL `ESC*b...W`/`V`, in cui `*bNNNNW` indica un blocco di NNNN byte di dati ([PCL 5 Printer Language Technical Reference Manual - ENWW](http://www.hp.com/ctg/Manual/bpl13210.pdf#:~:text=EN%20Transfer%20Raster%20Data%20Command,of%20raster%20graphics%20data%20that)).  
- I comandi `*bNNNNM`, `*bNNNNV`, `*bNNNNY` servono solo a impostare compressione o offset e non contengono dati utili ([*	Introduction	1-1](https://developers.hp.com/system/files/attachments/PCL%20Implementors%20Guide-23-Index%20by%20esc%20sequence.pdf#:~:text=Esc%2Ab%23M%20...............................................Compression%20Method.........................................................%2013,11%20Esc%2Ab%23X................................................X%20Offset)).  
- Lo script Python scansiona il file `.ful`, trova ogni sequenza `ESC*b...W`, ricava il valore numerico e legge i dati corrispondenti, infine concatena tutti i blocchi per ricostruire l’immagine firmware. 

Questa procedura dettagliata consente di **decodificare completamente il file di aggiornamento**, ottenendo così il binario flash che può essere analizzato o flashato separatamente. La conoscenza dei comandi PJL/PCL e la loro interpretazione è fondamentale per capire esattamente come i dati del firmware sono incapsulati nel file di update. 

```python
import re
import os

# === CONFIGURAZIONE ===
input_file = 'corfu_pp_usr_hf_CFP1FN2023BR_update_from_1515A_signed.ful'
output_folder = 'estratti'
output_file = 'firmware_ricostruito.bin'

# Crea la cartella di output
os.makedirs(output_folder, exist_ok=True)

# Carica tutto il file in memoria
with open(input_file, 'rb') as f:
    content = f.read()

# Trova tutti i comandi *bNNNNW
pattern = re.compile(rb'\*b(\d+)W')
matches = list(pattern.finditer(content))

segments = []

print(f"[INFO] Trovati {len(matches)} blocchi *bNNNNW")

for idx, match in enumerate(matches):
    size = int(match.group(1))
    command_start = match.start()
    command_end = match.end()

    data_start = command_end
    data_end = data_start + size

    if data_end > len(content):
        print(f"[WARNING] Blocco {idx}: dati fuori dal file, ignorato.")
        continue

    segment_data = content[data_start:data_end]
    segment_filename = os.path.join(output_folder, f'segment_{idx:03d}.bin')

    with open(segment_filename, 'wb') as s:
        s.write(segment_data)

    segments.append(segment_filename)

    print(f"[+] Blocco {idx}: Offset comando={command_start}, Inizio dati={data_start}, Dimensione={size} bytes")

# Assembla tutti i segmenti trovati
with open(output_file, 'wb') as out_f:
    for segment in segments:
        with open(segment, 'rb') as seg_f:
            out_f.write(seg_f.read())

print(f"\n[✔] Estrazione completata.")
print(f"[✔] Firmware assemblato in {output_file}")
```
**Fonti:** Riferimenti ufficiali HP PJL/PCL ([PCL 5 Printer Language Technical Reference Manual - ENWW](http://www.hp.com/ctg/Manual/bpl13210.pdf#:~:text=EN%20Transfer%20Raster%20Data%20Command,of%20raster%20graphics%20data%20that)) ([Printer Job Language Technical Reference Manual - ENWW](https://developers.hp.com/sites/default/files/PJL_Technical_Reference_Manual.pdf#:~:text=FSUPLOAD%20Command%20The%20FSUPLOAD%20command,is%20valid%3A%20%40PJL%20FSUPLOAD%20FORMAT%3ABINARY)) e analisi tecniche di firmware update ([*	Introduction	1-1](https://developers.hp.com/system/files/attachments/PCL%20Implementors%20Guide-23-Index%20by%20esc%20sequence.pdf#:~:text=Esc%2Ab%23M%20...............................................Compression%20Method.........................................................%2013,11%20Esc%2Ab%23X................................................X%20Offset)).
