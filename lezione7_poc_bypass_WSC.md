# Guida Tecnica al PoC C++ "MollyBus - WSC Bypass AV"

**MollyBus** è un Proof-of-Concept in C++ che dimostra tre funzionalità tipiche di un malware avanzato su sistemi Windows:

* **Registrazione al Windows Security Center (WSC) come antivirus fittizio** – Il codice si registra presso il Centro Sicurezza di Windows simulando la presenza di un software antivirus di terze parti.
* **Persistenza tramite Task Scheduler** – Il PoC configura un’attività pianificata all’avvio dell’utente per eseguire nuovamente il loader, garantendo persistenza dopo reboot o logout.
* **Iniezione di una DLL in un processo di sistema (explorer.exe/Taskmgr.exe)** – Il loader inietta una DLL (“MollyBus.dll”) in un processo di sistema designato (nel codice è `Taskmgr.exe`, ma concettualmente potrebbe essere *explorer.exe*), utilizzando tecniche di debug per aggirare restrizioni come gli Image File Execution Options.

Di seguito analizziamo in dettaglio il codice C++, organizzato nelle tre sezioni sopra elencate. Per ciascuna parte riporteremo gli spezzoni di codice pertinenti, ne spiegheremo il funzionamento e approfondiremo le API Win32/COM e i GUID utilizzati, descrivendone parametri, comportamento noto e implicazioni di sicurezza. L’analisi è rivolta a sviluppatori avanzati e ricercatori di sicurezza, con osservazioni su privilegi richiesti e possibili anomalie o considerazioni di sicurezza per ciascuna API.

## Registrazione al Windows Security Center come Antivirus Fittizio

Questa parte del PoC, implementata nella funzione `MollyBus::startup()`, sfrutta un’interfaccia COM non documentata di Windows Security Center per **registrare un finto prodotto antivirus**. In particolare, usa l’interfaccia denominata `IWscAVStatus` (presumibilmente “WSC AntiVirus Status”), ottenuta via COM con GUID non pubblici, per chiamare i metodi `Register()`, `Unregister()` e `UpdateStatus()`. Questo consente di far comparire il programma come antivirus attivo nel Centro Sicurezza, **senza** passare per i normali canali riservati ai vendor certificati.

Di seguito, suddividiamo il codice e spieghiamo ogni passo:

### Inizializzazione di COM e ottenimento dell’interfaccia WSC

```cpp
shared::ctx.deserialize();
logln("init: {:#x}", com_checked(CoInitialize(nullptr)));

auto inst = IWscAVStatus::get();
```

**Funzionamento:** Viene inizializzato il contesto applicativo e la libreria COM, quindi si ottiene un’istanza dell’interfaccia COM `IWscAVStatus`.

* `shared::ctx.deserialize()` deserializza da file (es. *ctx.bin*) lo stato persistente dell’applicazione (ad esempio, nome del finto AV e stato on/off precedente). Questo assicura che configurazioni salvate in esecuzioni precedenti (come il nome personalizzato dell’antivirus) vengano caricate in memoria all’avvio.

* `CoInitialize(nullptr)` inizializza il sistema COM per il thread corrente. In questo caso viene usato `CoInitialize` senza parametri, equivalente a `CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)`, ossia inizializzazione in single-threaded apartment (STA). Il wrapper `com_checked` verifica l`HRESULT` di ritorno e lancia eccezione in caso di errore. Un risultato `S_OK` (0) o `S_FALSE` viene loggato come esadecimale nel messaggio `"init: 0x0"` (in caso di successo). *Nota:* L’inizializzazione COM può fallire se è già stata chiamata con un altro modello di threading nel thread corrente; in tal caso verrebbe lanciata un’eccezione.

* `IWscAVStatus::get()` è una funzione helper che richiama internamentee `CoCreateInstance` per instanziare l’oggetto COM del WSC. In particolare, utilizza dei GUID **non documentati ufficialmente**:

  ```cpp
  static inline GUID detail::RCLSID = {…};       // CLSID del COM server WSC ISV
  static inline GUID detail::IID_IWscAVStatus = {…};  // IID dell'interfaccia IWscAVStatus

  IWscAVStatus* get() {
      IWscAVStatus* result = nullptr;
      com_checked(CoCreateInstance(detail::RCLSID, 0, CLSCTX_INPROC_SERVER,
                                   detail::IID_IWscAVStatus,
                                   reinterpret_cast<LPVOID*>(&result)));
      return result;
  }
  ```

  Qui `detail::RCLSID` rappresenta il **CLSID** (Class ID) dell’oggetto COM del Security Center responsabile dell’integrazione di antivirus di terze parti. Dai riferimenti disponibili, questo GUID corrisponde a `{F2102C37-90C3-450C-B3F6-92BE1693BDF2}`, che identifica la classe COM implementata presumibilmente in `wscisvif.dll` (“Windows Security Center ISV Interface”). Allo stesso modo, `detail::IID_IWscAVStatus` è l’**IID** (Interface ID) dell’interfaccia `IWscAVStatus` (GUID `{3901A765-AB91-4BA9-A553-5B8538DEB840}`). Questi GUID sono ottenuti tramite reverse engineering o strumenti come OleView, poiché non sono documentati pubblicamente: infatti l’API ufficiale WSC non espone direttamente funzioni per registrare un antivirus senza far parte del Microsoft Virus Initiative.

  **Dettagli tecnici:** La chiamata `CoCreateInstance` crea un oggetto COM del Security Center (CLSID indicato) in-process (`CLSCTX_INPROC_SERVER`) e ne richiede l’interfaccia `IWscAVStatus`. Se la chiamata ha successo, `inst` punterà a un oggetto COM attraverso cui invocare metodi come `Register`. Vale la pena notare che per istanziare questo COM **è necessario avere privilegi elevati**: tipicamente, il chiamante deve essere **amministratore** o contesto di sistema, altrimenti `CoCreateInstance` potrebbe fallire con `E_ACCESSDENIED` (0x80070005) o simili. Inoltre, da fonti non ufficiali si apprende che il processo chiamante dovrebbe idealmente essere **firmato con un certificato EV** perché Windows Security Center accetti pienamente la registrazione. Nel nostro PoC questa condizione non è soddisfatta (non c’è firma), ma a fini dimostrativi il codice tenta comunque la registrazione.

### Chiamata a Unregister per rimuovere eventuali AV registrati

```cpp
// Tentativo di deregistrare un precedente AV fittizio
logln("unregister: {:#x}", com_retry_while_pending([&inst](){
    return inst->Unregister();
}));

if (shared::ctx.state == shared::State::OFF) {
    return;
}
```

**Funzionamento:** Prima di registrare il nuovo antivirus fittizio, il codice prova a eseguire `Unregister()` sull’oggetto COM WSC ottenuto, e gestisce eventuali stati pendenti. In seguito, se lo stato desiderato (`shared::ctx.state`) è **OFF** (disabilitazione del finto AV), la funzione `startup()` termina subito dopo aver deregistrato l’AV precedente.

* `inst->Unregister()` invoca il metodo COM che rimuove il prodotto antivirus attualmente registrato nel WSC (se presente). Questo è utile per evitare duplicati: Windows Security Center in genere mantiene registrato un solo prodotto AV per volta per ogni categoria (antivirus, antispyware, firewall). Il PoC quindi esegue un *clean-up* preventivo. La chiamata è avvolta in `com_retry_while_pending` – un helper che riprova la chiamata COM se restituisce `E_PENDING`. `E_PENDING` indica che il WSC non era pronto a soddisfare la richiesta immediatamente (ad esempio, il servizio potrebbe essere occupato); la funzione in tal caso aspetta 5 secondi e ritenta finché non ottiene un risultato definitivo. Se c’è stato almeno un ritardo, attende un extra di 15 secondi prima di procedere, presumibilmente per dare tempo al Centro Sicurezza di aggiornare il proprio stato interno dopo l’operazione di unregister.

* Il risultato dell’`Unregister()` viene loggato (in formato esadecimale HRESULT). Un valore `S_OK` (0x0) indica che l’eventuale AV precedente è stato deregistrato correttamente; se non c’era nulla da deregistrare, è possibile che la funzione COM ritorni un errore oppure semplicemente `S_OK` senza effetto. Il codice non interrompe l’esecuzione se `Unregister()` fallisce, a meno che l’errore generi un’eccezione non gestita – ma usando `com_retry_while_pending` eventuali errori diversi da E\_PENDING non sono passati a `com_checked`, quindi non causano throw immediato (infatti `com_retry_while_pending` restituisce l’HRESULT finale senza controllarlo). In un contesto reale, se *unregister* fallisse, il successivo *register* potrebbe comunque sovrascrivere lo stato precedente.

* Il blocco `if (shared::ctx.state == shared::State::OFF) return;` verifica lo **stato richiesto**: la variabile `shared::ctx.state` è stata impostata in precedenza (durante `setup_context` nel main) a ON oppure OFF in base agli argomenti passati al programma (flag `-d` per disabilitare). Se è OFF, significa che l’utente o il configurazione vuole *disattivare* la protezione fittizia; in tal caso, dopo aver eventualmente rimosso la precedente registrazione, il codice esce. In pratica, questo consente di usare il programma con `--disable` per **deregistrarsi dal WSC**, rimuovendo l’AV fasullo (ad esempio per pulire il sistema), senza effettuare nuove registrazioni. Al contrario, se lo stato è ON (default), il codice prosegue per registrare/attivare il finto antivirus.

**Dettagli tecnici e sicurezza:** L’API COM `Unregister()` di `IWscAVStatus` presumibilmente deregistra *il prodotto associato al contesto corrente*. Non accetta parametri, quindi si basa sul fatto che l’oggetto COM `inst` sia associato ad un particolare prodotto (forse memorizzato internamente a livello di istanza COM, ad esempio l’ultimo registrato). Questo è un comportamento atipico rispetto alle comuni interfacce (ci si aspetterebbe un identificatore del prodotto da deregistrare), ma essendo un’interfaccia privata può avere questo stato interno. Una possibile spiegazione è che l’oggetto COM creato tramite `CoCreateInstance` di quella classe WSC mantenga un riferimento al “prodotto attivo” per quella sessione. In termini di sicurezza, chiamare `Unregister` **non richiede parametri**, quindi è semplice, ma può fallire se non ci sono AV registrati (ad esempio se nessun antivirus di terze parti è attualmente presente, magari solo Windows Defender attivo; tuttavia Windows Defender potrebbe implementare questa stessa interfaccia separatamente). Fallimenti di *Unregister* non impediscono necessariamente la registrazione successiva, ma idealmente andrebbero gestiti.

### Preparazione del nome e chiamata a Register()

```cpp
auto name_w = std::wstring(shared::ctx.name.begin(), shared::ctx.name.end());
if (name_w.empty()) {
    throw std::runtime_error("AV Name can not be empty!");
}
auto name = SysAllocString(name_w.c_str());
defer->void { SysFreeString(name); };
```

**Funzionamento:** Prima di effettuare la registrazione, il codice prepara il **nome del prodotto antivirus** da comunicare al WSC, convertendolo in un formato adatto.

* `shared::ctx.name` contiene il nome (stringa ANSI/UTF-8) scelto per l’antivirus fittizio, recuperato dal contesto (che a sua volta deriva dall’argomento `-n` passato al programma, oppure dal valore di default). Nel PoC, se non specificato diversamente, il nome di default è impostato a `names::kRepoUrl`, cioè l’URL del repository GitHub del progetto. Questo valore di default è probabilmente indicativo (forse per suggerire di dare una stella al repository), ma **in un contesto reale dovrebbe essere sostituito con un nome più plausibile di prodotto antivirus** (ad esempio “MyAV” o simili). Conviene infatti che il Centro Sicurezza mostri un nome riconoscibile all’utente (“Antivirus X è attivato”).

* `std::wstring name_w` converte la stringa `shared::ctx.name` in una stringa wide (Unicode UTF-16) `name_w`. Il metodo scelto è il costruttore da iteratori begin/end, ottenendo la codifica UTF-16 necessaria per interagire con COM (che su Windows usa stringhe wide nelle BSTR). Subito dopo, se la stringa risulta vuota, viene lanciata un’eccezione: **WSC non accetta nomi vuoti**, per cui il PoC impone questa verifica per evitare di chiamare Register con parametri vuoti che causerebbero errore.

* `SysAllocString(name_w.c_str())` alloca un **BSTR** contenente la stringa Unicode. `BSTR` è il tipo di stringa usato dalle API COM (trattasi di un buffer con prefisso contenente la lunghezza). Qui si utilizza la funzione COM di libreria `SysAllocString` passando il puntatore a wchar della std::wstring. Il risultato è assegnato a `name` (di tipo `BSTR`). Subito dopo, il codice usa un oggetto `defer` per assicurare che `SysFreeString(name)` venga chiamato alla fine della funzione, deallocando il BSTR. Questo è importante per evitare leak di memoria COM.

A questo punto la stringa BSTR `name` è pronta per essere passata alle successive chiamate COM `Register` e `UpdateStatus`.

**Dettagli tecnici:** Il nome scelto verrà utilizzato sia come **display name** del prodotto antivirus nel Centro Sicurezza, sia (come vedremo) come percorso all’eseguibile firmato. Nel PoC si usa lo stesso valore per entrambi i campi della registrazione, probabilmente per semplificare la dimostrazione. In uno scenario reale, *displayName* dovrebbe essere il nome leggibile (es. “FakeAV Test”), mentre *pathToSignedProductExe* dovrebbe essere un percorso file completo a un eseguibile firmato digitalmente (il binario principale dell’antivirus). L’uso improprio di un URL come percorso non corrisponde a un file reale, ma il fatto che la chiamata possa comunque riuscire suggerisce che WSC potrebbe **non validare immediatamente l’esistenza del file o la firma** durante la `Register()` – potrebbe semplicemente memorizzare i valori forniti. (È possibile che la validazione avvenga solo quando il Centro Sicurezza deve mostrare lo stato o quando il servizio di sicurezza verifica periodicamente la presenza del processo indicato). In ogni caso, fornire un path non valido o non firmato potrebbe limitare la credibilità della registrazione: in ambienti moderni, Windows potrebbe ignorare o segnalare come non verificato il prodotto.

Dal punto di vista dei **prerequisiti**, arrivati qui assumiamo che il processo sia in esecuzione con **privilegi amministrativi** (o sistema). Questo perché, come già notato, l’istanza COM del WSC probabilmente richiede privilegi elevati. Inoltre, se in esecuzione come utente normale non amministratore, la registrazione di un antivirus di terze parti non dovrebbe essere consentita per questioni di integrità del sistema (un malware senza privilegi non dovrebbe poter ingannare il Centro Sicurezza facilmente). Il PoC non esegue esplicitamente nessuna elevazione UAC, quindi sta al ricercatore eseguirlo da un prompt con diritti amministrativi.

### Registrazione dell’Antivirus fasullo con Register()

```cpp
logln("register: {:#x}", com_checked(inst->Register(name, name)));
```

**Funzionamento:** Qui avviene la **chiamata chiave**: il PoC invoca `inst->Register(name, name)` sul COM ottenuto. Questo dovrebbe registrare il prodotto antivirus nel WSC utilizzando i parametri forniti.

* Viene passato `name` sia come primo parametro che come secondo parametro. In base all’analisi delle interfacce WSC (ad esempio dalla documentazione interna e riferimenti su SystemCenter Wiki), la firma attesa è probabilmente `Register(BSTR pathToSignedProductExe, BSTR displayName)`. Il PoC dunque sta passando lo stesso valore in entrambi: il BSTR contentente di default. Se l’interfaccia interpreta letteralmente il primo parametro come *path*, registrerebbe quell’URL come percorso eseguibile. Questo è anomalo, ma se la chiamata restituisce S\_OK il Centro Sicurezza potrebbe temporaneamente accettarlo. In un utilizzo corretto, ci si aspetterebbe qualcosa come `Register(L"C:\\Program Files\\MyAV\\myav.exe", L"My Antivirus")`.

* La funzione `com_checked` avvolge la chiamata: quindi **se `Register` restituisce un HRESULT diverso da 0 (S\_OK)**, verrà lanciata un’eccezione che interrompe l’esecuzione. Se invece ritorna S\_OK, il codice continua e logga `"register: 0x0"`. Possibili errori includono: `E_INVALIDARG` (in caso di parametri nulli o vuoti – evitato dalla verifica precedente), oppure errori specifici se la registrazione fallisce (ad esempio se il processo non è adeguatamente firmato o autorizzato, il servizio potrebbe ritornare un codice di errore).

**Dettagli tecnici:** L’interfaccia `IWscAVStatus` è parte di un meccanismo interno introdotto (a quanto pare) a partire da Windows 10 per permettere agli antivirus di terze parti di comunicare il loro stato al sistema. Microsoft richiede che i vendor aderiscano al programma MVI (Microsoft Virus Initiative) e utilizzino API private o la registrazione come servizio protetto per integrarsi nel Security Center. In particolare, la chiamata `Register()` molto probabilmente:

* Registra internamente un nuovo prodotto AV con il *display name* fornito.
* Salva il percorso all’eseguibile firmato (che potrebbe essere usato per verificarne la presenza o per legarlo a un *Security Provider*).
* Potrebbe aggiornare lo stato del Centro Sicurezza indicando “è presente un antivirus di terze parti” (spostando Windows Defender in stato passivo).

Non è noto se `Register` sovrascriva automaticamente un’eventuale registrazione esistente (anche se diversa); per questo il PoC fa *Unregister* manuale prima. Da notare che l’oggetto COM utilizzato potrebbe mantenere il contesto di quel particolare prodotto registrato poi per le successive chiamate, ad esempio `UpdateStatus`.

**GUID e contesto COM:** Internamente, la chiamata COM viene gestita dal servizio *Security Center*. Il CLSID `{F2102C37-...}` corrisponde a un **Inproc COM Server** registrato nel registro di sistema (sotto HKCR\CLSID{GUID}) che dovrebbe puntare a una DLL di sistema (come `wscisvif.dll`). Dunque, quando chiamiamo CoCreateInstance, il sistema carica quella DLL e richiama DllGetClassObject su di essa, ottenendo un factory per creare un oggetto COM. La nostra interfaccia `IWscAVStatus` punta a questo oggetto. Il fatto che sia Inproc (in-process) significa che gira nel nostro processo, ma dietro le quinte potrebbe comunicare con il servizio di Windows Security (ad esempio via RPC) poiché il Security Center è normalmente implementato come servizio in esecuzione (es. `SecurityHealthService.exe`). Questo dettaglio si riflette nel fatto che `Register` e altre chiamate potrebbero restituire `E_PENDING` se il servizio remoto è occupato.

**Sicurezza:** Una volta registrato con successo, il Centro Sicurezza di Windows dovrebbe riflettere la presenza del nostro *fake AV*. Ciò significa che:

* In Windows 10/11, nella sezione **Sicurezza di Windows -> Protezione da virus e minacce**, potrebbe apparire un messaggio tipo “L’antivirus è gestito da un’app fornita dall’utente” oppure vedere il nome personalizzato. In alcuni casi, Windows Defender potrebbe disattivarsi (o segnalare che è gestito da organizzazione/altro software) poiché il sistema crede di avere un altro antivirus attivo.
* Questa tecnica potrebbe essere usata da malware per **disabilitare Windows Defender senza modificarne i setting direttamente**, semplicemente facendogli credere che c’è già un AV in funzione. È un *bypass* conosciuto: registrare un fake AV per prendere il posto di Defender.
* Tuttavia, se il nostro prodotto non aggiorna correttamente lo stato (ad es. firma non valida o UpdateStatus mancante), il Centro Sicurezza potrebbe segnalarlo con uno stato di attenzione (es. “Il tuo antivirus potrebbe essere disattivato” oppure “Stato sconosciuto”).

Va sottolineato che la riuscita di questa chiamata in un ambiente reale potrebbe essere ostacolata da misure di sicurezza: su sistemi aggiornati, Microsoft richiede che il *pathToSignedProductExe* punti a un file firmato con **certificato EV e attestato via Microsoft**, altrimenti potrebbe non considerare valido il prodotto. Il PoC, non avendo firma, potrebbe funzionare solo parzialmente (ad esempio vediamo l’AV comparire ma magari marcato come “non in esecuzione” se il servizio nota che il processo non esiste). La chiamata successiva `UpdateStatus` serve proprio a evitare questo, segnalando esplicitamente che l’antivirus è attivo.

### Aggiornamento dello stato di protezione con UpdateStatus()

```cpp
logln("update: {:#x}", com_checked(inst->UpdateStatus(WSCSecurityProductState::ON, 3)));
```

**Funzionamento:** Dopo la registrazione, il PoC chiama `UpdateStatus(...)` per aggiornare lo stato operativo dell’antivirus registrato. Passa due parametri: lo stato e un valore intero aggiuntivo.

* Il primo parametro è `WSCSecurityProductState::ON`. Nel codice questa è un’enumerazione definita come:

  ```cpp
  enum class WSCSecurityProductState : std::uint32_t {
      ON = 0, OFF = 1, SNOOZED = 2, EXPIRED = 3
  };
  ```

  Questi valori corrispondono agli stati possibili di un prodotto di sicurezza nel Centro Sicurezza:

  * **0 (ON)** – Il prodotto è attivo e in esecuzione.
  * **1 (OFF)** – Il prodotto è disattivato.
  * **2 (SNOOZED)** – Il prodotto è temporaneamente sospeso (ad esempio l’utente l’ha disabilitato per un periodo).
  * **3 (EXPIRED)** – Il prodotto è scaduto (licenza scaduta o definizioni non aggiornate da troppo tempo).

  Passando `ON` (0), il PoC indica che l’antivirus fittizio è attualmente acceso e funzionante.

* Il secondo parametro passato è `3`. Non è immediatamente documentato a cosa si riferisca questo valore. Dall’analisi di *reverse engineering* del WSC, si ipotizza che sia il **security product substatus** – molto probabilmente rappresenta lo stato delle *signature/definitions* dell’antivirus (ovvero se le definizioni virus sono aggiornate). Documenti interni indicano un’altra enum correlata, `_WSC_SECURITY_SIGNATURE_STATUS`, con valori:

  * 0 = **Out-of-date** (definizioni non aggiornate)
  * 1 = **Up-to-date** (definizioni aggiornate)

Tuttavia, il valore `3` passato qui non corrisponde ai due sopra. È possibile che nelle versioni attuali dell’interfaccia, il secondo parametro non sia più semplicemente 0/1 ma possa codificare ulteriori informazioni. Più probabilmente il secondo parametro è relativo alle **definizioni virali**: potrebbe darsi che 3 sia usato come *flag* per indicare qualcosa come “firmware/engine not up to date” oppure un codice arbitrario. Un’ipotesi: forse 3 indica uno stato di *expired* per le definizioni. Ad esempio, alcuni antivirus segnalano “abbonamento scaduto” o “definizioni scadute” che potrebbe essere rappresentato con questo valore. In ogni caso, è una scelta atipica. Idealmente, per indicare che è tutto OK, ci aspetteremmo `UpdateStatus(ON, 1)` (ON + up-to-date). Per segnalare definizioni obsolete, ON + 0. L’uso di 3 qui potrebbe essere un bug o un valore che nei test funzionava per far sì che WSC non considerasse Defender attivo (forse *EXPIRED* forza comunque Windows a considerare presente un AV anche se con problemi).

* Anche questa chiamata è avvolta in `com_checked`, quindi se fallisce lancia eccezione e blocca l’esecuzione. Un esito S\_OK verrà loggato come `"update: 0x0"`.

**Dettagli tecnici:** `UpdateStatus` è molto probabilmente il metodo con cui l’antivirus di terze parti segnala al Security Center il suo stato in tempo reale: acceso/spento, e aggiornato/non aggiornato. Il Centro Sicurezza utilizza queste informazioni per allertare l’utente se, ad esempio, l’antivirus è disattivato (OFF) o se le definizioni non sono aggiornate. Nel PoC, chiamando `UpdateStatus(ON, 3)` subito dopo la registrazione:

* Si informa il WSC che il prodotto è attivo.

* Il secondo parametro anomalo potrebbe far sì che WSC segnali comunque qualche stato (forse “azioni necessarie” se interpretato come EXPIRED). Alcuni snippet PowerShell suggeriscono che WSC considera *EXPIRED* come condizione che richiede attenzione, simile a OFF/SNOOZED. Se così fosse, il Centro Sicurezza potrebbe mostrare un’icona gialla di attenzione sul finto AV (dicendo magari che la protezione è scaduta). Questo potrebbe essere voluto per dimostrazione (far comparire comunque qualcosa).

* Dal punto di vista implementativo, all’interno del Security Center la chiamata potrebbe essere instradata a qualcosa come un metodo `CWscIsv::UpdateStatusAV(state, sigState)`. I nomi suggeriscono *Isv* (Independent Software Vendor). Il fatto che l’interfaccia sia privata spiega perché non ci sia documentazione chiara dei parametri.

**Considerazioni di sicurezza:** Una volta registrato e aggiornato lo stato, **Windows crederà di avere un antivirus installato**. Questo disabilita la protezione in tempo reale di Windows Defender (sui sistemi in cui Defender si disattiva in presenza di altro AV). Quindi, paradossalmente, eseguendo questo PoC su una macchina, si ottiene l’effetto di *spegnere Defender* lasciando però il sistema senza una vera protezione – un enorme potenziale buco di sicurezza se sfruttato da malware. Va ribadito che questa interfaccia COM non è pubblica: è riservata ai prodotti certificati; l’uso da parte di codice non autorizzato costituisce un abuso e potrebbe lasciare tracce (ad esempio, l’**Event Viewer** potrebbe registrare eventi sul Security Center). Inoltre, su Windows 10/11 moderni, Microsoft potrebbe aver introdotto controlli: per esempio solo processi firmati da Microsoft o da vendor affidabili (certificati) possono effettivamente riuscire a eseguire queste chiamate senza che poi il Security Center le ignori. Il PoC dimostra che tecnicamente è possibile chiamarle, ma l’efficacia potrebbe variare in base alle patch di Windows.

*N.B.*: Nel codice, dopo `UpdateStatus`, la funzione `startup()` termina (esce dallo scope) liberando le risorse COM allocate. Non viene esplicitamente chiamato `CoUninitialize()`, il che sarebbe buona pratica chiamare dopo aver finito con COM (specialmente perché era stata fatta una CoInitialize). In un processo semplice la mancata chiamata di CoUninitialize non ha grossi impatti (il sistema libererà risorse al termine del processo comunque), ma in contesti più complessi potrebbe essere rilevante.

Questa parte del codice ha lo scopo di **ingannare** Windows facendogli credere che il nostro processo (e la DLL correlata) sia un antivirus. È un ottimo esempio di come i malware possano abusare di funzionalità di sistema previste per software legittimo al fine di disabilitare difese.

## Persistenza tramite Task Scheduler

Il PoC implementa la persistenza creando una **attività pianificata** che esegue il loader all’accesso dell’utente. Questo approccio è comune per ottenere esecuzione automatica ad ogni avvio (persistenza), sfruttando l’infrastruttura di Windows Task Scheduler invece di, ad esempio, chiavi di registro Run.

Il codice relativo si trova principalmente nelle funzioni `loader::add_to_autorun()` e `loader::remove_from_autorun()`. Di seguito analizziamo come viene creata l’attività schedulata e quali API COM di Task Scheduler 2.0 vengono chiamate.

### Inizializzazione COM e connessione al servizio Task Scheduler

```cpp
HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
if (FAILED(hr)) {
    return false;
}
…
ITaskService* service = nullptr;
hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                      IID_ITaskService, reinterpret_cast<void**>(&service));
if (FAILED(hr)) {
    return false;
}
…
hr = service->Connect(VARIANT{}, VARIANT{}, VARIANT{}, VARIANT{});
if (FAILED(hr)) {
    return false;
}
```

**Funzionamento:** Il codice inizia aprendo un contesto COM multithreaded e creando l’oggetto COM principale del Task Scheduler, quindi si connette al servizio scheduler locale. Queste chiamate sono eseguite all’interno della funzione helper interna `with_service()`, che incapsula l’intera logica e infine richiama un callback per creare/eliminare il task.

* `CoInitializeEx(nullptr, COINIT_MULTITHREADED)` inizializza COM per l’uso multi-thread (MTA). Questo è diverso da prima, dove avevamo usato STA. Il motivo è che l’API Task Scheduler spesso richiede MTA (la documentazione Microsoft consiglia di inizializzare COM come multithreaded per usare Task Scheduler API, probabilmente perché internamente il servizio è multi-threading e alcune chiamate potrebbero bloccare se in STA). Se la inizializzazione fallisce (ad esempio ritorna RPC\_E\_CHANGED\_MODE se COM era già inizializzato STA su questo thread), la funzione esce restituendo false, segnalando il fallimento nel creare la persistenza.

* `CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&service)` crea un oggetto COM di classe TaskScheduler. Questa è la classe COM esposta dal sistema per interagire con il servizio di pianificazione. `CLSID_TaskScheduler` è un GUID standard definito in `<taskschd.h>` (valore `{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}`) e identifica la classe *Microsoft Task Scheduler* (versione 2.0). `IID_ITaskService` (GUID `{2FABA4C7-4DA9-4013-9697-20CC3FD40F85}`) è l’ID dell’interfaccia **ITaskService**. Questa interfaccia consente di **connettersi al servizio di schedulazione** e ottenere cartelle di attività. La chiamata CoCreateInstance restituisce un puntatore all’interfaccia ITaskService (memorizzato in `service`). Si usa `CLSCTX_INPROC_SERVER` perché la libreria che fornisce l’interfaccia è registrata come COM in-process (in realtà il Task Scheduler ha anche un servizio Windows, ma l’API espone un COM local-server oppure un proxy; internamente Windows instanzia l’oggetto e comunica col servizio di scheduling).

  *Nota:* Si linka anche la libreria `taskschd.lib` nel codice (vedi `#pragma comment(lib, "taskschd.lib")` in cima al file) per risolvere i GUID e le definizioni dell’API Task Scheduler.

* `service->Connect(VARIANT{}, VARIANT{}, VARIANT{}, VARIANT{})` chiama il metodo **ITaskService::Connect** per connettersi al servizio di Task Scheduler in esecuzione sulla macchina locale. I quattro `VARIANT{}` passati come parametri corrispondono a: server name, user, domain, password – tutti vuoti, perché si vuole connettersi al **Task Scheduler locale** con le credenziali correnti. In questo caso, passando tutti parametri vuoti, la connessione viene fatta come l’utente corrente al servizio sul localhost.

  * Se la chiamata ha successo (S\_OK), significa che ora abbiamo un oggetto `ITaskService` effettivamente connesso e pronto a manipolare le attività sul sistema.
  * Se fallisce, potrebbe essere per mancanza di autorizzazioni o problemi di servizio. Ad esempio, se l’utente corrente non ha privilegi sufficienti (in genere serve essere nel gruppo **Administrators** per registrare attività a livello di sistema, o quantomeno l’API consente di registrare task nell’ambito utente corrente con restrizioni). Il PoC però tenta di creare il task con runLevel Highest, quindi implica che deve essere un admin ad eseguirlo, come vedremo.

* L’oggetto `service` viene rilasciato automaticamente alla fine (c’è un `defer` che chiama `service->Release()` per evitare leak COM). Questo pattern RAII manuale viene applicato a tutti gli oggetti COM creati.

**Dettagli tecnici:**

* **ITaskService** è l’entry point dell’API Task Scheduler 2.0 (introdotta da Vista in poi). Sostituisce le vecchie API Task Scheduler 1.0 (che erano basate su **ITask** interfaccie COM diverse e file .job).
* `CLSID_TaskScheduler` gestisce in-process la comunicazione col servizio di sistema *Schedule*. In pratica quando chiamiamo Connect, il nostro processo tramite COM sta effettuando chiamate RPC al servizio *Task Scheduler* (spesso indicato come *Schedule Service*, gestito da `svchost.exe`).
* I parametri vuoti in Connect:

  * Il **server name** vuoto indica il computer locale (avremmo potuto specificare un altro computer sulla rete, se opportuno e con i permessi, per manipolare task in remoto).
  * **user**, **domain**, **password** vuoti indicano di connettersi con l’account corrente (il quale deve avere privilegi per le operazioni successive). È possibile connettersi come un altro utente (ad esempio user amministratore) specificando credenziali, ma qui non necessario perché presumiamo di essere già admin.
* Se Connect restituisse `HRESULT` di errore, il PoC esce. Un tipico errore potrebbe essere `HRESULT 0x80070534` (se l’account utente non è tradotto) o `0x80070005` (accesso negato). Ma dato che molto probabilmente si esegue come admin, Connect di solito riesce.

**Sicurezza:** Il Task Scheduler ha i propri controlli ACL. Per creare o modificare task nel root folder (path “\”), occorre essere **amministratori**. Un utente standard non può creare task a livello di sistema con privilegi elevati. Il codice imposta un task con `RunLevel=Highest` e logon interactive, che tipicamente richiede privilegi admin per registrarlo correttamente (almeno su Windows 10, se un utente standard prova a creare un task con runLevel highest per se stesso, ottiene errore). Inoltre, scrivendo nel Root folder (piuttosto che nella cartella riservata all’utente), l’utente deve far parte di Administrators.

In generale, questa parte del PoC **presuppone privilegi amministrativi** già ottenuti (ad esempio tramite UAC bypass o ingegneria sociale). Un malware reale potrebbe utilizzare l’ottenimento di admin via exploit o UAC bypass e poi installare un task pianificato persistente come qui.

### Creazione e configurazione del Task pianificato di autorun

Una volta connessi al servizio, il PoC procede a definire il task di persistenza. Il tutto avviene nel lambda passato a `with_service()`, che riceve `ITaskService* service` e un handle alla root folder. Vediamo passo passo le chiamate principali per creare il task:

```cpp
ITaskFolder* root_folder = nullptr;
hr = service->GetFolder(BSTR(L"\\"), &root_folder);
// Ottenuto l'oggetto radice delle cartelle di attività

root_folder->DeleteTask(BSTR(kTaskName.data()), 0);
// (Ignora errori) elimina un eventuale task "MollyBus" esistente

ITaskDefinition* task = nullptr;
hr = service->NewTask(0, &task);
// Crea un nuovo oggetto Task vuoto

IRegistrationInfo* reg_info = nullptr;
hr = task->get_RegistrationInfo(&reg_info);
// Ottenute le info di registrazione del task

reg_info->put_Author(_bstr_t(names::kRepoUrl.data()));
// Imposta l'autore del task (es. URL GitHub progetto)

IPrincipal* pPrincipal = nullptr;
hr = task->get_Principal(&pPrincipal);
// Ottenuto oggetto Principal per impostare l'utente/privilegi

// ... (rilascio di reg_info, pPrincipal gestiti da defer)
```

**Funzionamento:** Si ottiene la cartella radice delle attività pianificate, si elimina un task precedente con lo stesso nome se esiste, e si crea un nuovo *TaskDefinition* su cui settare proprietà di base come autore e principal.

* `service->GetFolder(L"\\", &root_folder)` restituisce un oggetto **ITaskFolder** che rappresenta la cartella root `"\"` (la directory principale dove sono registrate tutte le attività pianificate visibili in Utilità di Pianificazione sotto *Library\Task Scheduler*). Questo oggetto consente di enumerare, creare o eliminare task in quella cartella. Nel PoC, `root_folder` viene usato immediatamente per cancellare e poi registrare il nuovo task.

* `root_folder->DeleteTask(BSTR(kTaskName.data()), 0)` prova a eliminare un eventuale task esistente con nome uguale a `kTaskName`. `names::kProjectName` è definito come `"MollyBus"`, quindi il task pianificato avrà nome `"MollyBus"`. L’eliminazione è chiamata con flag 0 (nessuna opzione extra). Il codice **non controlla** l’HRESULT di ritorno di DeleteTask (lo chiama e basta, senza if), perché molto probabilmente non importa se fallisce (es. se il task non esiste, restituisce `HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)`). Si ignora l’errore e si procede comunque. Questo garantisce che eventuali esecuzioni ripetute di `add_to_autorun` non creino duplicati ma sovrascrivano il task esistente. *Nota:* la scelta di eliminare prima e poi creare è ridondante, perché più sotto si userà `TASK_CREATE_OR_UPDATE` che gestisce già l’overwrite. Ma è comunque un’ulteriore pulizia.

* `service->NewTask(0, &task)` crea un nuovo oggetto vuoto di definizione del task (**ITaskDefinition**). Il parametro `0` è riservato (deve essere 0). Se S\_OK, otteniamo un puntatore in `task`. Questo oggetto rappresenta in memoria la configurazione del task (triggers, azioni, impostazioni, ecc.) prima di registrarlo. Tutte le successive chiamate `get_X()` e `put_Y()` lavorano su questo oggetto **non ancora salvato**.

* `task->get_RegistrationInfo(&reg_info)` ottiene l’interfaccia **IRegistrationInfo**, usata per impostare metadati del task come Autore, Descrizione, Identificatore. Il PoC ottiene `reg_info` e subito dopo chiama `reg_info->put_Author(...)` passando `_bstr_t(names::kRepoUrl.data())`. `_bstr_t` è una classe utility del header `<comdef.h>` che gestisce BSTR in C++ in modo RAII. Qui costruisce un BSTR dal const char\* fornito (il progetto definisce `names::kRepoUrl` = `"https://github.com/es3n1n/MollyBus"`). Quindi l’**autore** del task viene impostato a quella stringa (che compare poi nelle proprietà avanzate del task in Utilità di Pianificazione). È un valore arbitrario; solitamente gli antivirus o software potrebbero mettere il proprio nome o dell’azienda come Author. Nel PoC, l’autore è un URL, il che è anomalo ma irrilevante ai fini funzionali.

* `task->get_Principal(&pPrincipal)` ottiene l’interfaccia **IPrincipal** associata al task. L’oggetto Principal definisce l’account sotto cui il task girerà e il livello di privilegio. Nel PoC, dopo ottenere `pPrincipal`, non viene impostato esplicitamente un nome utente (di default, se non si specifica, sarà l’utente corrente al momento della registrazione, oppure nessuno se logon type non è specifico – ma vedremo che nel RegisterTaskDefinition si userà `TASK_LOGON_INTERACTIVE_TOKEN` che implica l’utente corrente). La cosa che viene impostata è il **RunLevel**:

  ```cpp
  pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
  ```

  (Questa chiamata è presente più avanti, la citiamo qui per contesto). `TASK_RUNLEVEL_HIGHEST` indica che il task, all’esecuzione, dovrà essere lanciato col massimo livello di privilegio disponibile per l’utente (tipicamente: se l’utente è amministratore, run as admin; se utente standard, nessuna elevazione). In pratica, spuntando “Esegui con privilegi più elevati” nella UI di Utilità di Pianificazione. Ciò significa che quando il task si attiverà, se l’utente appartiene ad Administrators, il Task Scheduler eseguirà il processo con token elevato **senza necessità di prompt UAC** (poiché il servizio di scheduling lo può fare automaticamente). Questa impostazione è fondamentale: assicura che il loader parte all’avvio **con privilegi di amministratore**, evitando che UAC blocchi la persistenza. Dal punto di vista della sicurezza, è chiaro perché solo un admin possa creare un task con RunLevel=Highest.

* Tutti gli oggetti COM ottenuti (`root_folder`, `task`, `reg_info`, `pPrincipal`, ecc.) vengono rilasciati con `->Release()` tramite costrutti `defer` in fondo al blocco lambdas, per garantire il cleanup indipendentemente da errori intermedi.

**Dettagli tecnici:**

* L’oggetto `ITaskDefinition` include diverse proprietà accessibili con `get_X`: *RegistrationInfo*, *Triggers*, *Actions*, *Settings*, *Principal*, ecc. Il PoC configura ciascuna di queste sezioni.
* `IRegistrationInfo::put_Author` prende un BSTR (stringa) come autore. Non vi sono implicazioni di sicurezza dirette su questo campo; è puramente descrittivo.
* `IPrincipal::put_RunLevel(TASK_RUNLEVEL_HIGHEST)` corrisponde internamente a impostare l’esecuzione “Esegui con privilegi più elevati”. Il valore `TASK_RUNLEVEL_HIGHEST` è costante (1) che differisce da `TASK_RUNLEVEL_LUA` (0, esegui con privilegi limitati). Se l’utente che registra il task è admin, la presenza di Highest farà sì che il task quando scatta giri come elevato; se l’utente non è admin, il task può essere registrato (forse in cartella utente) ma runlevel highest non può comunque eseguire oltre i suoi diritti. Nel contesto attuale, siccome l’utente è admin, ciò equivale a un meccanismo di auto-elevazione senza prompt al prossimo logon (comodo per malware post-UAC bypass).

### Configurazione del Trigger di esecuzione all’accesso utente

```cpp
ITriggerCollection* trigger_collection = nullptr;
hr = task->get_Triggers(&trigger_collection);

ITrigger* trigger = nullptr;
hr = trigger_collection->Create(TASK_TRIGGER_LOGON, &trigger);
// Crea un trigger di tipo "Logon"

 // (rilascio di trigger_collection e gestione trigger con defer)
```

**Funzionamento:** Qui si crea un **Trigger** che farà scattare l’attività in corrispondenza di un evento di logon.

* `task->get_Triggers(&trigger_collection)` ottiene la collezione di trigger (interfaccia **ITriggerCollection**) associata al task. Un task può avere multipli trigger (es. a logon, ogni giorno alle 10, all’evento X, etc.). Si ottiene la collezione per poi aggiungere un nuovo trigger.

* `trigger_collection->Create(TASK_TRIGGER_LOGON, &trigger)` crea un nuovo trigger nella collezione, di tipo **TASK\_TRIGGER\_LOGON**. Il primo parametro è un enum `TASK_TRIGGER_TYPE2` – in questo caso il valore costante per il trigger “At logon” (all’accesso dell’utente). Questa chiamata restituisce un **ITrigger** generico, ma in realtà sarà un oggetto più specifico (internamente COM sa che un logon trigger è un `ILogonTrigger`, che deriva da ITrigger). Comunque, per impostare le proprietà base comuni non serve fare QueryInterface a ILogonTrigger nel nostro caso, perché non stiamo specificando un utente.

  * Se volessimo, potremmo castare a `ILogonTrigger` e chiamare `ILogonTrigger::put_UserId` per specificare che il trigger vale per un certo utente. Nel PoC questo non avviene, quindi per default il trigger di logon si applica a **qualunque utente acceda**? In realtà, c’è un dettaglio: quando il task verrà registrato con `TASK_LOGON_INTERACTIVE_TOKEN`, quel parametro potrebbe legare il task all’utente corrente. È un po’ confuso:

    * `TASK_TRIGGER_LOGON` senza specificare user in trigger significa “triggera all’accesso di *qualunque* utente” a sistema.
    * Ma se durante registrazione indichiamo che il task deve girare con l’**Interactive Token** di un utente specifico, di solito quell’attività appare sotto la cartella specifica dell’utente. In effetti, c’è la possibilità che questo task venga creato nella *Task Scheduler Library* generale oppure nella sezione “Attività Utente”.
    * Data la chiamata `folder->RegisterTaskDefinition(_bstr_t(kTaskName.data()), ...)` nel root folder e `TASK_LOGON_INTERACTIVE_TOKEN`, sospetto che in realtà il Task risulterà valido solo per l’utente che lo crea. Nei Task Scheduler, `TASK_LOGON_INTERACTIVE_TOKEN` indica che *nessuna credenziale viene salvata*, l’esecuzione avviene solo quando quell’utente è loggato. E il nome del task è globale. Quindi se un altro utente (anche admin) fa logon, potrebbe non eseguire il task, perché il task è registrato per quell’utente specifico (non è molto ben documentata questa combinazione, ma in pratica crea un task con la proprietà “Esegui solo se l’utente X ha effettuato l’accesso”).

  In sintesi, il trigger è “All’accesso utente”, il che soddisfa la persistenza: non appena l’utente corrente effettua login (dopo reboot, o logoff/logon), il task si attiverà.

* Ogni oggetto COM creato viene rilasciato: `trigger_collection->Release()` e `trigger->Release()` con i `defer` opportuni.

**Dettagli tecnici:**

* `TASK_TRIGGER_LOGON` è uno dei tanti tipi di trigger possibili (altri includono TIME, DAILY, WEEKLY, EVENT, etc.). Logon trigger può avere la proprietà opzionale UserId; se non impostata, di default il trigger si applica a *qualsiasi logon di qualsiasi utente*. Nel contesto di un task registrato per l’utente corrente, significa effettivamente “quando quell’utente fa logon” (perché anche se scatta per altri, il task non può girare con token di altri a meno di specifiche diverse).
* Non vengono impostate altre proprietà del trigger (come Delay, RepeatInterval, ecc.) – non necessario, quindi il trigger è immediato all’evento di logon.
* Un possibile rischio/nota: se il task fosse creato globalmente con logon trigger per tutti, un malware potrebbe voler nascondersi su un sistema multiutente. In questo PoC, focalizzato sulla dimostrazione, la distinzione non è approfondita.

**Sicurezza:** Creare un scheduled task come persistenza è generalmente meno sospetto di mettere qualcosa in Run? Non esattamente: gli strumenti di sicurezza controllano anche i task pianificati. Tuttavia, un task può essere configurato in modo granulare (es. esegui solo se condizione X) per cercare di nascondersi meglio. Qui è molto semplice: all’accesso utente, esegui. Questo è facile da individuare in uno scan di persistenze.

Dal punto di vista dei permessi, ribadiamo: creare un logon trigger in root folder con runlevel highest richiede admin. Un utente standard potrebbe invece creare un task nella cartella riservata al suo SID. In quel caso avrebbe dovuto usare `TASK_LOGON_GROUP` o `TASK_LOGON_PASSWORD` con credenziali. Il PoC sceglie di usare l’account corrente (admin) e interactive token (niente password salvata).

### Configurazione dell’Azione (esecuzione del loader con parametro)

```cpp
IActionCollection* action_collection = nullptr;
hr = task->get_Actions(&action_collection);

IAction* action = nullptr;
hr = action_collection->Create(TASK_ACTION_EXEC, &action);
// Crea un'azione di tipo "esegui un exec"

IExecAction* exec_action = nullptr;
hr = action->QueryInterface(IID_IExecAction, (void**)&exec_action);
// Ottiene l'interfaccia specifica IExecAction

exec_action->put_Path(_bstr_t(bin_path.string().c_str()));
exec_action->put_Arguments(_bstr_t("--from-autorun"));
```

**Funzionamento:** Viene creata l’azione da compiere quando il trigger scatta, ovvero eseguire l’eseguibile del loader. Si configura il percorso e gli argomenti dell’azione.

* `task->get_Actions(&action_collection)` ottiene la collezione di azioni (**IActionCollection**) del task. Un task può avere più azioni da compiere in sequenza (il caso più comune è una singola azione). Si aggiungerà un’azione di tipo *Exec*.

* `action_collection->Create(TASK_ACTION_EXEC, &action)` aggiunge una nuova azione di tipo **Esegui un programma**. `TASK_ACTION_EXEC` è il tipo costante (0, in pratica) per indicare un’azione di esecuzione. Viene restituito un puntatore generico **IAction**. Analogamente al trigger, internamente COM crea un oggetto concreto (`IExecAction` implementazione) ma inizialmente viene dato come IAction.

* `action->QueryInterface(IID_IExecAction, (void**)&exec_action)` richiama QueryInterface sul IAction appena creato per ottenerne l’interfaccia più specifica **IExecAction**. Questo è necessario per impostare proprietà specifiche dell’azione di esecuzione, come il percorso dell’eseguibile, gli argomenti, la working directory, etc. Una volta ottenuto `exec_action`, abbiamo i metodi `put_Path` e `put_Arguments`.

* `exec_action->put_Path(...)` imposta il percorso del programma da eseguire. Il PoC calcola prima `bin_path = shared::get_this_module_path()`, cioè il path completo dell’eseguibile corrente (il loader stesso). Infatti, in `add_to_autorun()` si fa `const auto bin_path = shared::get_this_module_path();`. Questo presumibilmente restituisce qualcosa come `C:\...\<cartella>\MollyBus-loader.exe` (il nome del loader). Quindi `bin_path.string().c_str()` è questo percorso in formato wide string convertito in char (o direttamente std::filesystem::path -> string). Il `_bstr_t(...)` converte in BSTR.

  * Esempio: se il PoC loader risiede in `C:\Users\Utente\Downloads\MollyBus.exe`, quell sarà il path eseguito all’avvio.
  * È importante usare il path assoluto, altrimenti il Task Scheduler non saprebbe dove trovare l’eseguibile.

* `exec_action->put_Arguments(_bstr_t("--from-autorun"))` imposta gli argomenti della riga di comando da passare al programma. In questo caso viene passato il flag `--from-autorun`. Questo è utilizzato nel main del programma: se il loader viene avviato con `--from-autorun`, saprà di essere stato lanciato dalla persistenza e potrà comportarsi di conseguenza (ad esempio, nel codice main, evitano di aprire la console utente e di sovrascrivere il file di contesto, oltre a saltare la pausa finale). Quindi questo argomento è una **indicazione al programma stesso** di eseguire in modalità silente.

  * Nel PoC, `program.add_argument("--from-autorun").hidden().default_value(false).implicit_value(true)` definisce quell’opzione nascosta. E nel codice, `if (!config.from_autorun || config.verbose) shared::alloc_console();` fa sì che la console venga allocata solo se *non* è from\_autorun a meno che verbose sia richiesto. In altre parole, se partito da autorun e non in verbose, niente console. Inoltre, più avanti nel main c’è: `if (!config.from_autorun) system("pause");`, così da non bloccare se avviato automaticamente. Ciò dimostra una buona progettazione per distinguere runtime utente vs autorun.

* Anche gli oggetti di azione vengono rilasciati con `Release` tramite defer.

**Dettagli tecnici:**

* `IExecAction` deriva da `IAction` ed espone `put_Path`, `put_Arguments`, `put_WorkingDirectory`. Il PoC non imposta la working directory, quindi per default sarà probabilmente la directory di sistema o quella corrente del Task Scheduler (che in esecuzione di utente interattivo dovrebbe essere qualcosa come `%USERPROFILE%` o `%windir%System32` – tipicamente i task girano con working dir `C:\Windows\system32` se non specificato).
* Se il percorso contiene spazi, conviene racchiuderlo tra virgolette; l’API TaskSched presumo lo faccia automaticamente se necessario, o comunque passando come singola string il path completo con spazi funziona (non c’è bisogno di manualmente aggiungere doppi apici, l’API memorizza il path e argomenti separati).
* `_bstr_t` è un wrapper che qui semplifica la conversione string-to-BSTR. Alternativamente si poteva usare SysAllocString come altrove.
* Una volta impostato Path e Args, l’azione è configurata. Non c’è necessità di chiamare `IAction::put_Id` o simili (c’è possibilità di dare un ID all’azione, ma non serve in genere).

**Sicurezza:** Il path configurato è quello dell’eseguibile corrente. Ciò significa che la persistenza lancia nuovamente *lo stesso loader exe*. In uno scenario reale, il malware potrebbe copiare il proprio binario da qualche parte più “stealth” (es. dentro ProgramData) e puntare a quello. Nel PoC si suppone che si stia semplicemente testando, quindi va bene usare lo stesso percorso.

* Bisogna considerare che se l’utente sposta o elimina l’exe, il task di autorun rimarrebbe orfano (puntando a file inesistente). Ma per un PoC va bene.
* Utilizzare Task Scheduler per eseguire un binario su disk è individuabile tramite analisi forense: rimane un file su disco e un task registrato. Un avversario potrebbe invece scegliere di creare un task che lancia un comando PowerShell encoded, ecc., per evitare file evidenti. Qui comunque registriamo il binario esistente.
* Dal punto di vista dei privilegi: grazie a `RunLevel=Highest`, quando il task esegue il loader, questo partirà **con privilegi elevati** (se l’utente fa parte di Admin). Ciò significa che la catena di persistenza mantiene i permessi admin. Se nel frattempo l’utente revocasse i privilegi admin, il task potrebbe non eseguirsi con successo o eseguirsi con token limitato (non del tutto chiaro: un utente admin de-elevato a standard senza rimuoverlo dai admin group? Comunque scenario poco probabile durante una sessione, e al logon successivo se le credenziali cambiano il task forse non eseguirebbe affatto per quell’utente).
* Un aspetto importante è che Task Scheduler memorizza i task in XML sotto `C:\Windows\System32\Tasks\` (nel caso root). Il nome del file sarebbe “MollyBus”. Questo rimane sul file system, leggibile dagli admin. Inoltre, la definizione può essere letta interrogando l’API (un analista può fare `schtasks /Query /XML` per vedere i dettagli). Quindi non è invisibile, ma i malware spesso si affidano a utenti che non controllano l’elenco dei task pianificati.

### Impostazioni aggiuntive del Task

```cpp
ITaskSettings* settings = nullptr;
hr = task->get_Settings(&settings);

settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
settings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
```

**Funzionamento:** Vengono recuperate le impostazioni generali del task e modificate due opzioni relative alla batteria, per assicurare che l’attività giri anche se il computer è su batteria (non in alimentazione AC) e non si interrompa in caso di passaggio a batteria.

* `task->get_Settings(&settings)` fornisce l’interfaccia **ITaskSettings**, che racchiude varie opzioni (es. consentire esecuzione a batteria, wake the computer, idle settings, etc.).

* `settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE)` imposta l’opzione “Non avviare se il computer è alimentato a batteria” a **FALSE**, ossia **consenti** l’avvio su batteria. Di default, alcuni task possono avere questa opzione TRUE per evitare consumi indesiderati; qui vogliamo che la persistenza avvii comunque, anche su laptop non collegato alla rete elettrica.

* `settings->put_StopIfGoingOnBatteries(VARIANT_FALSE)` imposta “Interrompi se si passa a batteria” a FALSE, ossia **non interrompere** il task se durante la sua esecuzione il computer passa all’alimentazione a batteria. Per un task che esegue un programma breve all’avvio non è fondamentale, ma il PoC li disabilita per sicurezza, cosicché nulla possa impedire al loader di partire/completare per via dello stato di alimentazione.

* Non vengono toccate altre impostazioni, ma l’ITaskSettings offre molte opzioni: IdleSettings, ExecutionTimeLimit, Priority, Hidden ecc. Nel PoC non è necessario cambiare altro; si potrebbe voler impostare `settings->put_Enabled(VARIANT_TRUE)` (ma di default un nuovo task è enabled) o `put_StartWhenAvailable(VARIANT_TRUE)` se fosse, ad esempio, un trigger perso. Non rilevante qui.

**Dettagli tecnici:** Queste chiamate semplicemente settano flag booleani. Usano `VARIANT_FALSE` che è definito come `((VARIANT_BOOL)0)` nel mondo COM. Dato che i metodi accettano `VARIANT_BOOL` (che è tipicamente `short` con valori `VARIANT_TRUE` = -1, `VARIANT_FALSE` = 0), vengono passati quei costanti.

**Sicurezza:** Disabilitare le restrizioni di batteria è comune per i malware, in modo da non perdere un’esecuzione in caso un laptop non sia collegato. Non ha implicazioni di sicurezza particolari se non garantire che il task avvii sempre. Va ricordato che *ITaskSettings* potrebbe avere un’opzione `Hidden` – utile per nascondere il task dall’interfaccia grafica di Utilità di Pianificazione. Il PoC non chiama `settings->put_Hidden(VARIANT_TRUE)`, quindi il task **non sarà nascosto**: sarà visibile nella lista (anche se con nome non immediatamente sospetto per un utente medio, ma per un occhio attento “MollyBus” può destare curiosità). Un malware reale probabilmente imposterebbe Hidden=TRUE per celare il task all’interfaccia standard (anche se rimane visibile via comandi e query WMI).

### Registrazione del Task nel sistema

```cpp
IRegisteredTask* registered_task = nullptr;
hr = folder->RegisterTaskDefinition(
    _bstr_t(kTaskName.data()), task, TASK_CREATE_OR_UPDATE,
    VARIANT{}, VARIANT{}, TASK_LOGON_INTERACTIVE_TOKEN,
    _variant_t(L""), &registered_task);
    
return SUCCEEDED(hr);
```

**Funzionamento:** Questa è la chiamata finale che effettua la **registrazione effettiva** del task precedentemente configurato, rendendolo persistente nel sistema.

* `folder->RegisterTaskDefinition(...)` è un metodo dell’interfaccia **ITaskFolder**. I parametri che accetta sono:

  1. **Name** (BSTR): il nome dell’attività. Qui `_bstr_t(kTaskName.data())` passa il nome `"MollyBus"` come BSTR.
  2. **ITaskDefinition**: l’oggetto task da registrare (il puntatore `task` creato e configurato).
  3. **Flags** (int): opzioni di creazione. Si usa `TASK_CREATE_OR_UPDATE` (valore 6), che indica: crea il task se non esiste, oppure aggiorna quello esistente con lo stesso nome. Questo permette di evitare errori se il task esisteva già (lo si sovrascrive).
  4. **UserId** (VARIANT): specifica l’utente sotto cui registrare il task. Qui viene passato `VARIANT{}` vuoto. In combinazione con il logon type (vedi dopo), significa che l’utente è implicito. Poiché si usa `TASK_LOGON_INTERACTIVE_TOKEN`, il `UserId` vuoto indica l’**utente corrente** (che ha chiamato Connect). In altri scenari: per logon type “password” bisognerebbe specificare un username.
  5. **Password** (VARIANT): non usato per `INTERACTIVE_TOKEN` (infatti passiamo anche qui `VARIANT{}` vuoto). Se il logon type fosse `TASK_LOGON_PASSWORD`, qui si passerebbe la password in chiaro (da notare: il Task Scheduler la criptografa in registrazione, ma l’API la vuole).
  6. **LogonType** (TASK\_LOGON\_TYPE): tipo di logon richiesto. Il PoC usa `TASK_LOGON_INTERACTIVE_TOKEN`. Questo indica che **il task verrà eseguito solo quando l’utente è loggato e usando il suo token**; non vengono memorizzate credenziali. In pratica, il task “appartiene” all’utente corrente e non può girare se l’utente non fa logon interattivo. Altri valori possibili: `TASK_LOGON_BATCH` (per girare anche senza logon, richiede salvare credenziali), `TASK_LOGON_SERVICE_ACCOUNT` (per usare account di sistema come SYSTEM), `TASK_LOGON_NONE` (raro, per alcuni trigger speciali).
  7. **sddl** (VARIANT): stringa SDDL per definire le ACL di sicurezza del task. Viene passato `_variant_t(L"")`, cioè una BSTR vuota. Questo significa che verranno assegnati i permessi di default (di solito: accesso al task consentito all’utente specificato e agli admin, etc.). Un malware potrebbe restringere ulteriormente l’ACL per impedire ad altri utenti di modificare il task, ma qui non è fatto.

  L’ultimo parametro è l’out **IRegisteredTask**: un puntatore all’oggetto appena registrato (istanza concreta salvata). Il PoC lo riceve in `registered_task` ma non lo utilizza, se non per rilasciarlo subito dopo.

* `SUCCEEDED(hr)` viene usato per restituire un booleano: se `RegisterTaskDefinition` torna S\_OK (o anche S\_FALSE, considerato successo, ma in questo caso o è S\_OK o errore), la funzione `add_to_autorun()` restituirà true. Se c’è errore, false. Il chiamante (nel main, `process_autorun()`) stamperà un messaggio del tipo "\*\* added to autorun: 1/0" a seconda del booleano.

**Dettagli tecnici:**

* Durante `RegisterTaskDefinition`, il Task Scheduler service valida le informazioni e salva il task. Con `TASK_LOGON_INTERACTIVE_TOKEN` e utente implicito, il task viene tipicamente salvato sotto **\Task\\** (root) con l’autorizzazione legata all’utente corrente. In effetti, se un altro amministratore guardasse la lista tasks, vedrebbe “MollyBus” e come *Autore* il nome account corrente (il PoC ha impostato Author diverso, ma l’owner effettivo sarà l’account). Non essendoci credenziali salvate, il servizio non eseguirà il task se l’utente non è loggato.

* Se si volesse che il task partisse allo startup di macchina, bisognerebbe usare `TASK_TRIGGER_BOOT` e un logonType di tipo service account (ad es. `TASK_LOGON_SERVICE_ACCOUNT` con user `LOCAL SYSTEM`), che richiede privilegio SE\_INTERACTIVE\_LOGON. Il PoC invece preferisce il logon utente (forse perché come PoC utente è più comodo, e anche perché per service account serve run as system).

* Il nome del task è “MollyBus”. Si poteva mascherare con un nome più innocuo. Persistenze reali a volte usano nomi di sistema plausibili (es: “Chrome Updater Task” finto). “MollyBus” è abbastanza unico e riconoscibile.

* **Errori possibili:** Se un task con quel nome esiste ma è in esecuzione, `RegisterTaskDefinition` con CREATE\_OR\_UPDATE dovrebbe comunque aggiornare (la documentazione dice che in caso di conflitto viene sovrascritto). Se c’è un problema di permessi (ad esempio utente non admin tentando di scrivere in root), potrebbe dare `E_ACCESSDENIED`. Se l’XML generato avesse qualche incoerenza, potrebbe dare `HRESULT_FROM_WIN32(ERROR_INVALID_DATA)`, ma essendo configurato via API è difficile. Un caso: se `RunLevel=Highest` e il task è per utente standard non admin, la registrazione *potrebbe* essere rifiutata (non ho certezza, ma potrebbe considerarlo non valido combinare Highest con un utente che non ha privilegi, benché forse lo lascia e all’atto pratico non eleva).

* La funzione `remove_from_autorun()` nel PoC chiama semplicemente `with_service` passando una lambda vuota che ritorna true. Dato che `with_service` cancella comunque il task all’inizio, questa funzione in pratica **rimuove la pianificazione** (chiamando DeleteTask come visto) e basta. Non è necessario replicare la logica di creazione: basta connettersi e cancellare. Nel main, se l’utente esegue il loader con `-d/--disable`, allora `shared::ctx.state` è OFF e `process_autorun` chiamerà `remove_from_autorun()` stampando "\*\* removed from autorun: 1".

**Sicurezza:** Una volta registrato, il task garantirà l’esecuzione del loader a ogni logon dell’utente. Se l’utente ha i privilegi admin, l’esecuzione sarà con elevazione automatica. Questo meccanismo può sopravvivere a reboot (perché è nel Task Scheduler persistente su disco).

* Un utente avanzato o un amministratore potrebbe notare il nuovo task pianificato ed eliminarlo manualmente per rimuovere la persistenza (es. via `schtasks /Delete /TN "MollyBus"` oppure da interfaccia). Il PoC non fa nulla per nascondere il task (non c’è Hidden, non c’è nome camuffato), perché immagino scopo didattico.
* In scenari reali, la persistenza via Task Scheduler è preferita rispetto a chiavi Run se il malware vuole ottenere esecuzione elevata senza UAC: infatti una voce in `HKLM\Run` verrebbe eseguita all’avvio utente ma con token normale, mentre un Task schedulato con runlevel highest può elevare. Questo è un noto **UAC bypass/persistence** trick – ma necessita scrivere nel Task Scheduler che è già azione privilegiata.
* Il servizio di Task Scheduler gira come SYSTEM, quindi è lui che alla condizione di trigger lancia il processo con gli attributi specificati. Ciò significa anche che, se il binario del loader venisse rimosso, il Task resterebbe attivo ma genererebbe errore ad ogni logon (visibile nel registro di Utilità Pianificazione). Durante test, conviene rimuovere il task chiamando l’opzione `--disable` o manualmente, per evitare chiamate a vuoto.

Abbiamo quindi coperto come il PoC aggiunge e rimuove la propria persistenza mediante un’attività pianificata. Questo garantisce che la porzione di codice di *registrazione WSC e iniezione* venga eseguita a ogni nuovo accesso, mantenendo l’antivirus fittizio sempre registrato finché il task rimane.

## Iniezione della DLL nel processo di sistema (explorer.exe/Taskmgr.exe)

La terza componente del PoC riguarda l’**iniezione di codice**: il loader C++ lancia un processo di sistema e vi inietta la DLL `MollyBus.dll`. Nel codice, il processo bersaglio (`names::kVictimProcess`) è definito come `"Taskmgr.exe"`, ovvero **Task Manager**. Il prompt dell’utente menzionava *explorer.exe*; concettualmente la tecnica è la stessa e potrebbe essere applicata a *explorer.exe*, ma nel PoC specifico si è optato per Task Manager (forse per evitare interferenze con Explorer che è costantemente in esecuzione). L’obiettivo è far girare la logica del finto AV (presumibilmente implementata nella DLL) all’interno di un processo di sistema fidato.

Questa sezione spiega il codice della funzione `loader::inject()` (in **inject.cpp**) e le chiamate Win32 utilizzate per realizzare l’iniezione:

### Preparazione dell’ambiente per evitare Image File Execution Options (IFEO)

```cpp
STARTUPINFOA si = { .cb = sizeof(si) };
PROCESS_INFORMATION pi = { 0 };
SECURITY_ATTRIBUTES sa = { .nLength = sizeof(sa), .bInheritHandle = TRUE };

native::get_peb()->read_image_file_exec_options = 0;
```

**Funzionamento:** Si definiscono le strutture necessarie per creare un nuovo processo e si modifica un parametro nel **PEB (Process Environment Block)** del processo corrente per disabilitare la lettura delle *Image File Execution Options* durante la creazione del processo bersaglio.

* `STARTUPINFOA si` e `PROCESS_INFORMATION pi` sono strutture standard per `CreateProcess`. `si.cb = sizeof(si)` inizializza la struttura startup info (versione ANSI in questo caso, poiché si userà CreateProcessA). Non vengono impostati altri campi di `si` manualmente, il resto rimane 0. `PROCESS_INFORMATION pi` è inizializzato a zero. Queste strutture verranno riempite da CreateProcess con le informazioni sul processo/thread creato.

* `SECURITY_ATTRIBUTES sa` è inizializzato con `nLength = sizeof(sa)` e `bInheritHandle = TRUE`. Questa struttura è usata per definire attributi di sicurezza per gli handle creati dal processo figlio e se questi devono essere ereditabili. Nel codice, passeremo `&sa` sia come `lpProcessAttributes` che `lpThreadAttributes` in CreateProcess, e metteremo `bInheritHandles = FALSE` nella chiamata, quindi l’uso di `sa` qui è un po’ ridondante (di solito, se `bInheritHandles` è FALSE, i SECURITY\_ATTRIBUTES possono essere null oppure con bInheritHandle irrilevante). In ogni caso definisce che se fosse abilitata l’ereditarietà, gli handle marcarti ereditabili potrebbero essere ereditati dal figlio. Non fondamentale qui.

* `native::get_peb()->read_image_file_exec_options = 0;` questa riga è importante: accede al **PEB (Process Environment Block)** del processo corrente e setta a 0 il flag `read_image_file_exec_options`. Il PEB è una struttura interna di ogni processo Windows che contiene molte informazioni sul processo stesso (moduli caricati, heap, ecc.). In particolare, l’offset 0x1 del PEB (secondo campo, dopo `InheritedAddressSpace`) è un byte chiamato `ReadImageFileExecOptions`. Quando questo flag è impostato a **FALSE (0)**, indica al loader di processo di **non leggere le Image File Execution Options dal registro** per il nuovo processo creato.

  * **Image File Execution Options (IFEO)**: sono impostazioni nel registro (sotto `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<ProcessName>.exe`) che possono includere parametri come *Debugger* (per lanciare un eseguibile alternativo al posto del processo, utile per debug o purtroppo anche per malware) o mitigazioni. Normalmente, quando chiamiamo CreateProcess, il sistema controlla nel registro se esistono chiavi IFEO per quel file eseguibile; ad esempio, se c’è un valore `Debugger`, invece di lanciare direttamente l’eseguibile, lancia il debugger specificato.
  * Impostando `read_image_file_exec_options = 0` **nel PEB del processo chiamante** stiamo indicando (grazie a una caratteristica interna di NTDLL) che per i successivi CreateProcess chiamati da questo processo, il sistema **salti la lettura delle IFEO**. In pratica, è un flag ereditabile: se il nostro processo non vuole che le IFEO vengano applicate ai figli, può disattivarlo.
  * Ciò viene fatto perché si sta per lanciare `Taskmgr.exe`. Alcuni sistemi o software di sicurezza potrebbero aver impostato IFEO su Taskmgr (ad esempio, alcuni malware usano IFEO per impedire all’utente di lanciare Task Manager o per lanciare un fake task manager). Anche alcuni tool di debugging potrebbero avere voci IFEO. Disabilitando la lettura, ci assicuriamo che **venga eseguito il vero Taskmgr.exe e non qualcos’altro**. Inoltre, combinato col flag di debug (vedi sotto), questo consente di bypassare eventuali misure come *Protected Process* o simili legate a IFEO. Nel commento nel codice si fa riferimento a un commento su GitHub issue, a riprova che questa tecnica è discussa dal autore.

**Dettagli tecnici:** Ottenere il PEB avviene tramite `native::get_peb()`, che usa `RtlGetCurrentPeb()` dall’NTDLL. Normalmente, il PEB non è documentato nelle API user-mode, ma i campi principali sono noti. Qui l’autore definisce una sua classe PEB minima con solo i campi necessari per posizionamento. Il campo `read_image_file_exec_options` è all’offset 1 (un byte). Lo impostiamo a 0 (FALSE).

Questa operazione richiede che il processo abbia accesso in scrittura al proprio PEB (che è sempre il caso finché sei il processo stesso, è in memoria locale). Non richiede privilegi speciali.

**Sicurezza:** Manomettere il PEB è una pratica non comune nelle applicazioni legittime, ma usata da alcuni malware/cheat per bypassare meccanismi di sistema. In questo caso, l’uso è relativamente benigno: evitare che un debugger definito via registro prenda il controllo del processo figlio. Un esempio di potenziale conflitto: su Windows, se c’è una chiave IFEO per `Taskmgr.exe` con valore `Debuggger = some.exe`, normalmente `CreateProcess("Taskmgr.exe")` lancerebbe `some.exe`. Il PoC vuole invece lanciare genuinamente Taskmgr (per poi iniettarlo), quindi disabilita quella deviazione. Questo può essere visto come tecnica **anti-anti-malware**: alcuni antivirus impostano IFEO su processi comuni per monitorarli; qui ci si sottrae a quel monitoraggio.

### Creazione del processo sospeso in modalità debug

```cpp
std::println("** booting {}", proc_name);
const auto process_flags = CREATE_SUSPENDED | DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS;
if (!CreateProcessA(
        nullptr, 
        const_cast<char*>(proc_name.data()),
        &sa, &sa, FALSE, process_flags,
        nullptr, nullptr, &si, &pi))
{
    throw std::runtime_error(std::format("unable to create process: {}", GetLastError()));
}
```

**Funzionamento:** Si avvia il processo bersaglio (`Taskmgr.exe`) in stato **sospeso** e sotto il controllo di un debugger (il nostro processo stesso come debugger). Se la creazione fallisce, viene lanciata un’eccezione con l’errore di sistema.

* `proc_name` è passato come parametro a `inject()` e corrisponde a `names::kVictimProcess` cioè `"Taskmgr.exe"`. Il codice fa un semplice log `** booting Taskmgr.exe` per debug console.

* Viene definita la maschera di flag `process_flags` combinando:

  * `CREATE_SUSPENDED` (0x00000004): il processo viene creato ma il suo thread primario rimane sospeso, quindi **non inizia ancora l’esecuzione**. Questo è fondamentale per poter iniettare codice prima che il processo esegua il suo codice (evitando che Task Manager si apra e magari interferisca).
  * `DEBUG_PROCESS` (0x00000001): indica che il processo figlio sarà in modalità debug con il **nostro processo corrente come debugger primario**. In altre parole, la chiamata CreateProcess non ritornerà finché non avremo attaccato come debugger (viene gestito internamente).
  * `DEBUG_ONLY_THIS_PROCESS` (0x00000002): assicura che solo il processo creato venga debuggato e non i suoi eventuali figli. Questo evita di essere invasi da eventi debug di altri processi nel caso il figlio ne crei.

  Usando questi due flag di debug, il nostro processo chiamante diventa il **debugger** del nuovo processo. Ciò ha due effetti:

  1. Gli eventi di creazione thread, modulo, eccezione nel figlio verrebbero riportati a noi (non che li stiamo gestendo attivamente, ma è la semantica).
  2. Più importante, quando c’è un debugger attivo, il sistema *non applica* certe misure al processo figlio. Ad esempio, se quell’eseguibile fosse protetto da qualche meccanismo PPL (Protected Process Light) o dovesse mostrare UI, col debugger presente possiamo manipolare il processo più liberamente.
  3. Collegato a quanto sopra, combinato con `read_image_file_exec_options = 0`, stiamo **bypassando eventuali debugger di IFEO**, perché: impostando DEBUG\_PROCESS, se esistesse una chiave IFEO Debugger per Taskmgr, il sistema la ignorerebbe comunque in quanto stiamo esplicitamente dicendo che saremo noi il debugger. L’opzione read\_image\_file\_exec\_options forse era un passo ridondante in presenza di DEBUG\_PROCESS, ma assicura al 100% di saltare quell’interferenza.

* `CreateProcessA(...)`: vengono passati i parametri classici:

  * `lpApplicationName = nullptr` e `lpCommandLine = const_cast<char*>(proc_name.data())`. Qui passiamo `"Taskmgr.exe"` come command line (il cast è necessario perché CreateProcessA non accetta const). Se ApplicationName è null, Windows proverà a risolvere il nome dell’eseguibile dalla command line cercandolo nelle cartelle di sistema e PATH. Nel nostro caso, **Taskmgr.exe** risiede in `C:\Windows\System32\Taskmgr.exe`. Il sistema dovrebbe trovarlo in System32 automaticamente perché System32 è nel PATH di sistema, oppure perché la funzione CreateProcess cerca nelle directory standard di Windows quando non trova altrove. (Va detto che passare solo il nome potrebbe fallire se PATH non include System32 per qualche motivo, ma di solito c’è. In alternativa, sarebbe stato più robusto specificare il percorso completo.)
  * `lpProcessAttributes = &sa`, `lpThreadAttributes = &sa`, `bInheritHandles = FALSE`. Anche se `sa.bInheritHandle = TRUE`, qui mettiamo FALSE, dunque non verranno ereditati handle. Il SECURITY\_ATTRIBUTES passa comunque possibili attributi di sicurezza (NULL DACL se avessimo voluto specificare, ma non lo facciamo, quindi eredita ACL default).
  * `dwCreationFlags = process_flags` (sospeso+debug come definito).
  * `lpEnvironment = nullptr` (ereditare le variabili d’ambiente del processo chiamante).
  * `lpCurrentDirectory = nullptr` (usare la current directory del chiamante o di Windows? Con null, di default su CreateProcess, dovrebbe usare la directory corrente del processo chiamante, che potrebbe essere dove risiede l’exe corrente. In contesti reali, magari vorremmo che Taskmgr partisse in System32 come working dir, ma non essenziale).
  * `lpStartupInfo = &si`, `lpProcessInformation = &pi` per ricevere info su processo e thread.

* Se CreateProcessA restituisce 0 (fallimento), `GetLastError()` fornisce l’errore. Il codice in quel caso lancia un’eccezione runtime con messaggio “unable to create process: <errore>”. Possibili errori: file non trovato (2), accesso negato (5). Ad esempio, se l’utente non fosse admin e tentasse di lanciare Taskmgr in modalità debug, potrebbe fallire per accesso negato a debug? In realtà, ogni utente può debug a sé stesso se ha privilegio di debug. Il privilegio **SeDebugPrivilege** non è richiesto per fare da debugger a un processo che *si sta creando* sotto la stessa utenza, penso. Quindi in pratica, se non trova Taskmgr.exe, errore 2; se qualche policy impedisce l’avvio, errore diverso. Dato che è admin, dovrebbe trovarlo e avviarlo.

* Dopo CreateProcess, `pi.hProcess` è l’handle al processo neonato, `pi.hThread` il handle del thread principale (sospeso) e `pi.dwProcessId` e `dwThreadId` gli ID.

**Dettagli tecnici:**

* **Processo sospeso**: Con `CREATE_SUSPENDED`, il thread principale di Taskmgr.exe è creato ma non eseguito. Ciò significa che il codice di Task Manager (che normalmente subito visualizzerebbe la finestra o inietterebbe se stesso in qualche meccanismo) non parte. Il processo esiste in stato suspended. In questo stato possiamo manipolarlo a piacimento (allocare memoria nel suo spazio, etc.) prima di eventualmente riprenderlo.
* **Modalità debug**: Essendo in debug, il sistema genera una serie di eccezioni e notifiche verso di noi (creazione processo, caricamento moduli, ecc.). Il PoC però **non le gestisce** (non c’è un WaitForDebugEvent loop). Tuttavia, subito dopo viene effettuato il detach (DebugActiveProcessStop). Finché non facciamo detach, il nuovo processo è stoppato in attesa degli eventi debug? In realtà, CreateProcess con DEBUG\_PROCESS ritorna *dopo* aver generato i debug events iniziali (credo li accoda a noi). Non gestendoli, se non detachassimo, il figlio rimarrebbe sospeso in attesa del debuggee. Fortunatamente qui stiamo per detachare subito.
* Con DEBUG\_PROCESS, il chiamante ottiene anche permessi elevati sul figlio – ad esempio può effettuare `WriteProcessMemory`, etc., senza dover chiamare OpenProcess con TOKEN speciali, perché come debugger ha un accesso quasi completo al processo debugged. Questo facilita l’iniezione (non c’è bisogno di chiamare OpenProcess con PROCESS\_ALL\_ACCESS, anche se in realtà qui il CreateProcess ci fornisce già l’handle con accesso completo).
* Vale la pena notare: aprire un processo protetto come *Task Manager* di solito non richiede privilegi particolari, essendo un normale processo di sistema lanciato dall’utente. Ma se si volesse iniettare in un processo come *explorer.exe* che è già in esecuzione, bisognerebbe usare OpenProcess con PROCESS\_VM\_WRITE/PROCESS\_CREATE\_THREAD, etc. Il PoC evita di attaccarsi a un processo esistente (che potrebbe essere protetto da antivirus), e preferisce creare un nuovo processo host, minimizzando potenziali restrizioni.

**Sicurezza:** Avviare un processo di sistema come Taskmgr in modalità sospesa e debug è un comportamento anomalo per un programma utente, ma non impossibile. Potrebbe attirare l’attenzione di alcune soluzioni di sicurezza che monitorano i debugger in azione o la creazione sospesa di processi critici. Tuttavia, questa tecnica è simile a quella usata per process hollowing o migrazione di processi in alcuni malware. Qui non sostituiamo l’immagine del processo, ma iniettiamo una DLL. Il vantaggio di usare un processo di sistema legittimo (Task Manager) è che la DLL iniettata potrebbe sembrare più fidata, e il processo stesso ha un nome noto. Il rovescio della medaglia è che l’utente potrebbe notare un Taskmgr nei processi anche quando non ha aperto il Task Manager. Alcuni malware invece scelgono *svchost.exe* o *explorer.exe* per confondersi meglio. Il PoC, essendo dimostrativo, probabilmente va bene così.

L’uso di DEBUG\_PROCESS richiede privilegi di debug per attaccare processi di altri utenti o di sistema. In questo caso creandolo noi come utente admin, non c’è bisogno di SeDebugPrivilege esplicito (che comunque un admin possiede). Se avessimo voluto attaccare un processo esistente come explorer, l’admin avrebbe potuto usare OpenProcess direttamente, ma qui preferiscono questa tecnica forse per bypassare IFEO e altre cose in un colpo solo.

### Distacco del debugger e preparazione all’iniezione

```cpp
// Detach dal processo debug
native::debug_set_process_kill_on_exit(false);
native::debug_active_process_stop(pi.dwProcessId);

CloseHandle(pi.hThread);
// (nota: non chiudiamo pi.hProcess qui, lo restituiamo al chiamante)
```

**Funzionamento:** Dopo la creazione, il codice **si sgancia dalla modalità debug** del processo figlio, così da lasciarlo proseguire normalmente (almeno per quanto riguarda l’attaccamento del debugger). Inoltre chiude l’handle del thread principale (che era sospeso) per pulizia, senza però terminare il thread (resta sospeso nel processo figlio).

* `native::debug_set_process_kill_on_exit(false)` invoca `DebugSetProcessKillOnExit(FALSE)` tramite la funzione wrapper definita. Normalmente, se un processo debug termina, Windows per default termina anche il processo debuggato (questo è il comportamento di default per evitare processi orfani in stato di attesa debug). Chiamando DebugSetProcessKillOnExit(FALSE), si dice al sistema di **non** uccidere il figlio se il debugger (noi) termina o si disconnette inaspettatamente. Questo è cruciale perché stiamo per disconnetterci deliberatamente: senza questa chiamata, chiamando DebugActiveProcessStop, il sistema potrebbe comunque terminare il processo debuggato (a seconda delle circostanze). Impostando false, indichiamo che quando ci staccheremo, il processo dovrà rimanere vivo.

* `native::debug_active_process_stop(pi.dwProcessId)` chiama `DebugActiveProcessStop(processId)` tramite wrapper. Questa API stacca il debugger attivo dal processo con quell’ID. In pratica, facciamo **detach** dal debug di Taskmgr.exe. Dopo questa chiamata:

  * Il nostro processo non riceverà più eventi di debug dal figlio.
  * Il processo figlio viene liberato dal controllo del debugger. Dato che era stato creato sospeso, rimane sospeso (perché non abbiamo ancora ripreso il thread).
  * Se c’erano eccezioni in sospeso, vengono risolte (nel senso che DebugActiveProcessStop le gestisce tutte come continue o terminate).
  * Adesso Taskmgr.exe è un normale processo sospeso, come se fosse stato creato con solo CREATE\_SUSPENDED (il debug non è più attivo).

* Gestione degli handle:

  * Il codice racchiude `CloseHandle(pi.hThread)` in un blocco `defer` nel listato originale, ma qui lo vediamo esplicitamente chiamato. Chiude l’handle del thread principale del processo figlio, perché non serve più tenerlo aperto. NON chiamano `ResumeThread` su di esso, quindi il thread *rimane sospeso* nel processo remoto! Questo è un dettaglio importante: significa che **Taskmgr.exe non verrà mai realmente eseguito** (il suo thread principale è chiuso ma non terminato – attenzione: *chiudere l’handle* non termina il thread, lascia il thread nello stato in cui era, solo che non abbiamo più un riferimento ad esso nel nostro processo).
  * L’handle del processo (`pi.hProcess`) invece **non viene chiuso** qui, infatti il commento dice “Not closing hProcess because we return it”. Il valore di ritorno della funzione `inject()` è definito come `HANDLE`, e infatti alla fine della funzione restituiamo `pi.hProcess`. Dunque il chiamante (il main, `load_MollyBus()`) riceve l’handle del processo creato. Questo handle verrà conservato per tutta la durata (servirà per terminare il processo alla fine, e forse per altre interazioni tramite la memoria condivisa).
  * Chiudere il handle del thread principale senza averlo mai ripreso è un approccio inusuale ma efficace: il thread esiste ancora nel sistema, e poiché non è stato ripreso rimane nello stato “wait: suspended”. Non avendo più l’handle, dal nostro processo non possiamo più riprenderlo (a meno di riaprirlo con OpenThread se volessimo). Ma non è necessario, perché lo scopo non è eseguire Task Manager, bensì **solo far girare la nostra DLL** dentro di esso. Come farà la DLL a girare se il thread principale è fermo? Lo vedremo: creiamo un thread remoto apposta. In pratica, stiamo usando Taskmgr.exe come un contenitore il cui main thread è in pausa infinita, e la nostra DLL girerà in parallelo.

**Dettagli tecnici:**

* `DebugSetProcessKillOnExit(FALSE)` deve essere chiamato prima di `DebugActiveProcessStop`, altrimenti il detach potrebbe terminare il processo (default era TRUE).
* Queste funzioni richiedono il PID (nel caso di DebugActiveProcessStop). Internamente, quando attivammo DEBUG\_PROCESS, eravamo automaticamente attaccati come debugger (non c’è bisogno di chiamare DebugActiveProcess, che sarebbe per attaccarsi a un processo già esistente). Per staccarsi, si usa DebugActiveProcessStop.
* Dopo il detach, il processo figlio non ha un debugger attivo, ma rimane sospeso perché il thread era creato sospeso e non è mai stato ripreso. Questo è un punto cruciale: un normale utilizzo di DEBUG\_PROCESS spesso comporta subito un ResumeThread per far partire il figlio e poi gestire breakpoints, ecc. Qui no, perché vogliamo iniettare prima.
* Rilasciando l’handle del thread, in teoria perdiamo la possibilità di manipolarlo direttamente. Tuttavia, potremmo comunque aprirlo di nuovo se necessario, essendo admin (OpenThread con rights se volessimo resume in futuro). Il PoC non lo fa mai: lascia il thread dormiente fino alla fine, e alla fine termina l’intero processo. Questo significa che *Task Manager non apparirà mai visibile*, il suo finestra non appare perché mai eseguita la WinMain. Quindi per l’utente, c’è un processo Taskmgr.exe in background che non fa niente se non ospitare la DLL.
* Tenere `pi.hProcess` aperto serve per successive operazioni (in questo caso, per il main thread che attende completamento e poi termina il processo). Finché abbiamo un handle aperto, possiamo terminare il processo in sicurezza con TerminateProcess, come infatti verrà fatto nel main.

**Sicurezza:** Distaccarsi dal debug evita di dover restare come debugger (che potrebbe essere rumoroso e rilevabile). Permette al processo di eseguire normalmente (una volta che decideremo di farlo proseguire, nel nostro caso eseguirà solo la DLL injection thread e stop). Questo step in sé è standard per process injection quando si usa il trick del debug.

* Un aspetto: avendo chiamato DebugActiveProcessStop, **il privilegio SeDebugPrivilege** potrebbe essere richiesto se stessimo attaccando un processo di un altro utente. In questo caso, siccome il processo l’abbiamo creato noi, dovrebbe appartenere allo stesso utente e non necessita quell’override. In contesti di injection in explorer (che gira come stesso utente, quindi ok) o in un servizio (allora admin deve avere SeDebugPrivilege se è di LocalSystem, ma admin ce l’ha di default).
* Il thread principale sospeso di Taskmgr significa che se qualcuno aprisse *Task Manager* vero manualmente, potrebbe trovarsi un conflitto: Windows potrebbe cercare di aprire un secondo Taskmgr perché uno risulta già esistente (non so se doppia istanza di Taskmgr è consentita – in genere no, di solito c’è un meccanismo che evita due istanze). È possibile che cliccando Ctrl+Shift+Esc, non succeda nulla perché un Taskmgr c’è già (il nostro in background). Ciò potrebbe far insospettire un utente tecnico. Un malware più furbo avrebbe scelto un processo che tipicamente ha più istanze o che non blocchi funzionalità utente. *Explorer.exe* magari era più invisibile sotto questo aspetto (anche se injection in explorer può destabilizzare il sistema se la DLL è crashy).

### Allocazione memoria e scrittura del path DLL nel processo remoto

```cpp
LPVOID mem = VirtualAllocEx(pi.hProcess, nullptr, dll_path.size() + 1,
                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
if (mem == nullptr) {
    throw std::runtime_error(std::format("unable to allocate memory: {}", GetLastError()));
}

// scrive la stringa del percorso DLL nella memoria remota
if (!WriteProcessMemory(pi.hProcess, mem, dll_path.data(),
                        dll_path.size() + 1, nullptr)) {
    throw std::runtime_error(std::format("unable to write memory: {}", GetLastError()));
}
```

**Funzionamento:** Alloca una porzione di memoria nel processo figlio e vi copia dentro la stringa con il percorso completo della DLL da iniettare.

* `dll_path` è stato preparato in `load_MollyBus()` nel main: in pratica, è il percorso completo di “MollyBus.dll” che il PoC vuole iniettare. Nel main abbiamo:

  ```cpp
  auto dll_path = shared::get_this_module_path().parent_path();
  dll_path /= names::kDllName; // "MollyBus.dll"
  if (!exists(dll_path)) throw ...;
  return loader::inject(dll_path.string(), names::kVictimProcess);
  ```

  Quindi `dll_path` (qui passato come string\_view a inject) è ad esempio `"C:\Users\Utente\Percorso\MollyBus.dll"`. Il main controlla anche che il file DLL esista, altrimenti errore. Questo è importante: deve esserci la DLL da iniettare accanto all’exe.

* `VirtualAllocEx(pi.hProcess, nullptr, dll_path.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)` alloca memoria nel **processo remoto** indicato da `pi.hProcess`. Parametri:

  * `pi.hProcess` è l’handle del processo target con permessi di memoria (grazie a CreateProcess con debug, abbiamo full access; VirtualAllocEx richiede PROCESS\_VM\_OPERATION).
  * `lpAddress = nullptr` lascia decidere al sistema dove allocare (non forziamo un indirizzo specifico).
  * `dwSize = dll_path.size() + 1` bytes – allochiamo esattamente la dimensione del percorso (in char, incluso il terminatore null). Se il path è 50 caratteri, allochiamo 51 byte.
  * `flAllocationType = MEM_COMMIT | MEM_RESERVE` – riserviamo e allochiamo la memoria fisica.
  * `flProtect = PAGE_READWRITE` – la memoria remota è allocata come leggibile e scrivibile (non eseguibile, non serve eseguire quel memory, conterrà solo dati).

  Se la funzione restituisce 0 (NULL), c’è un errore (ad esempio mancanza di memoria o permessi), si lancia eccezione con GetLastError. In contesti normali, questa piccola allocazione dovrebbe riuscire. Il pointer ritornato (in variabile `mem`) è l’indirizzo **nel processo remoto** dove è stata allocata la memoria. Non ha significato particolare nel nostro processo, ma ci serve solo passarlo a WriteProcessMemory e CreateRemoteThread.

* `WriteProcessMemory(pi.hProcess, mem, dll_path.data(), dll_path.size() + 1, nullptr)` copia i bytes dal buffer sorgente (qui il nostro string data) all’indirizzo `mem` del processo target. Viene copiato `dll_path.size() + 1` bytes, includendo il terminatore null, così nel processo remoto avremo una stringa C valida col path. Se restituisce 0 (FALSE), errore -> eccezione.

  * Da notare: `dll_path.data()` fornisce un `const char*` (stringa ANSI multi-byte) perché il codice ha usato `CreateProcessA` e presumibilmente userà `LoadLibraryA`. Dunque si sta passando un percorso ASCII. Se il percorso avesse caratteri non rappresentabili in ANSI (es. caratteri Unicode), potrebbe essere un problema. Ma immaginiamo percorsi standard ASCII per ora. Alternativamente, l’autore avrebbe potuto usare la versione wide con CreateProcessW e LoadLibraryW. Ha scelto A probabilmente per semplicità.
  * `WriteProcessMemory` richiede permesso PROCESS\_VM\_WRITE sul target (che abbiamo).
  * Il quinto parametro (lpNumberOfBytesWritten) è passato come nullptr, perché non ci serve sapere quanti byte sono stati scritti (se fallisse avremmo FALSE).

* Dopo questa operazione, nel processo target `Taskmgr.exe` (ancora sospeso) c’è in memoria (all’indirizzo mem) il path della DLL. Ad esempio, mem = 0x00245000 (valore arbitrario) nel suo spazio, e quell’area contiene "C:\Users\Utente\Percorso\MollyBus.dll\0".

**Dettagli tecnici:**

* Spesso i malware allineano la size a un multiplo di sistema (tipo 0x1000 = 4096 bytes, una pagina), ma qui va bene anche size precisa, VirtualAllocEx arrotonderà per eccesso a pagina (quindi allocherà probabilmente 4096 byte comunque).
* Avrebbero potuto anche scrivere la stringa wide e usare LoadLibraryW. Scegliendo la A, sperano che la DLL path non contenga caratteri non ANSI. Su sistemi internazionali, magari il nome utente ha caratteri unicode – questo potrebbe essere un bug potenziale se eseguito in tali ambienti (es. utente "José" con accent, il path "C:\Users\José...dll" in ANSI perde il carattere; LoadLibraryA potrebbe fallire se la conversione sbaglia). Comunque, come PoC va bene.
* Il pointer `mem` viene liberato in un defer successivo con `VirtualFreeEx(pi.hProcess, mem, 0, MEM_RELEASE)` **dopo** l’uso (vedi codice originale). Nel snippet mostrato, non vediamo il defer, ma è presente nel file, ciò significa che dopo injection, la memoria allocata sarà liberata. Tuttavia, riflettiamo: liberare la memoria subito dopo aver creato il thread potrebbe essere pericoloso, perché il thread remoto userà quella stringa. Idealmente bisognerebbe liberare la memoria solo dopo che LoadLibrary ha copiato la stringa internamente (LoadLibrary ovviamente legge il path string immediatamente). In questo caso, sincronizzando con WaitForSingleObject sul thread, è probabile che quando il thread termina, la LoadLibrary ha già letto il path (in realtà, LoadLibrary internamente prenderà il string path come parametro, ma come lo passa se è la stessa stringa? No, attenzione: CreateRemoteThread chiamerà kernel32!LoadLibraryA(mem). L’API LoadLibraryA all’interno del processo leggerà la stringa puntata da `mem` e poi libererà risorse allocate interne se necessario. Quando LoadLibraryA ritorna, quell’area di memoria non serve più. Quindi dopo WaitForSingleObject, è sicuro liberare mem).
* Quindi il defer VirtualFreeEx viene eseguito dopo WaitForSingleObject (grazie all’ordine del scope e come è definito). Va bene.

**Sicurezza:** Allocare memoria e scrivere dentro un altro processo è un’operazione tipica di injection. Molti antivirus/EDR rilevano chiamate a VirtualAllocEx + WriteProcessMemory come **indicatore di iniezione**. Farlo dentro Taskmgr.exe poi, se monitorato, farebbe scattare allarmi (perché Taskmgr di solito non riceve scritture di memoria da altri processi). Quindi anche se l’utente non vede nulla, un EDR potrebbe bloccare queste chiamate se non opportunamente mascherate.

* Non c’è molta mitigazione qui, è il classico pattern. In ambienti con Anti-Cheat (se stessimo attaccando un gioco ad esempio), chiamate debug attach o WriteProcessMemory vengono spesso bloccate.
* In contesto di malware vs antivirus, alcuni AV autoproteggono i loro processi contro queste operazioni (ma Taskmgr.exe non è protetto in genere).
* Permessi: Come admin, VirtualAllocEx/WriteProcessMemory su un processo di pari livello è consentito. Se eravamo utente limitato, su un processo di sistema non avremmo potuto (ma qui il target è un nostro processo figlio, quindi nessun problema).

### Creazione di un thread remoto per eseguire LoadLibraryA

```cpp
HANDLE thread = CreateRemoteThread(pi.hProcess, nullptr, 0,
    reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA),
    mem, 0, nullptr);
if (thread == NULL) {
    throw std::runtime_error(std::format("unable to create thread: {}", GetLastError()));
}

// Attende che DllMain termini
WaitForSingleObject(thread, INFINITE);
```

**Funzionamento:** Si crea un thread all’interno del processo target che eseguirà la funzione `LoadLibraryA` passando come argomento la stringa (indirizzo `mem`) contenente il percorso della DLL. Si attende poi indefinitamente finché questo thread remoto non termina, segno che la `LoadLibrary` ha completato (ovvero la DLL è stata caricata e il suo `DllMain` eseguito).

* `CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, mem, 0, NULL)` è la chiamata chiave per l’iniezione. Parametri:

  * `hProcess = pi.hProcess`: handle del processo in cui creare il thread (deve avere diritto PROCESS\_CREATE\_THREAD, che possediamo).

  * `lpThreadAttributes = NULL`: thread con security attributes di default.

  * `dwStackSize = 0`: stack size default (userà dimensione default del processo).

  * `lpStartAddress = (LPTHREAD_START_ROUTINE)LoadLibraryA`: l’indirizzo della funzione da eseguire nel thread remoto. Qui stiamo passando direttamente il puntatore alla funzione `LoadLibraryA` *della nostra process space*. **Attenzione tecnica:** Il cast è necessario per far tacere il compilatore (che vuole LPTHREAD\_START\_ROUTINE, definito come `DWORD (WINAPI*)(LPVOID)`). `LoadLibraryA` ha signature `HMODULE WINAPI LoadLibraryA(LPCSTR)`. In realtà, i tipi sono compatibili in memoria (ritorna HMODULE che su Windows x64 è 64-bit, ma come thread routine restituirebbe un DWORD sulla specifica 32-bit?). Su 64-bit Windows, LPTHREAD\_START\_ROUTINE è definito come `PVOID` ritorno credo, e quell mismatch potrebbe essere negligibile. Comunque, è prassi comune fare questo cast per usare LoadLibraryA come thread start. Più importante: **sta assumendo che l’indirizzo di LoadLibraryA sia lo stesso nel processo target.** Su Windows, kernel32.dll è modulare e con ASLR potrebbe caricarsi a indirizzi diversi per processi differenti. Tuttavia, è noto che per *processi a 64-bit su Windows 10+, i moduli di sistema spesso hanno base address randomizzata all’avvio del sistema ma poi fissa per tutti i processi.* Cioè, in un singolo boot, kernel32.dll può essere caricato in tutti i processi allo stesso indirizzo (address space layout randomization consistente). Se così, passare l’indirizzo di LoadLibraryA preso dal nostro processo funzionerà nel figlio. Se per qualche motivo l’indirizzo non coincidesse, il thread eseguirebbe in un indirizzo inesistente causando crash. Evidentemente, questa tecnica è molto diffusa e in pratica funziona quasi sempre. Su sistemi a 32-bit era molto spesso valida perché kernel32 veniva caricato allo stesso indirizzo in tutti i processi (0x7c800000 su XP per es.). Su 64-bit con ASLR, credo implementino il *ASLR by module, not by process* per moduli di sistema (non documentato ma empiricamente spesso vero).

  * Un modo robusto sarebbe stato: get handle di kernel32.dll nel target e GetProcAddress remoto di LoadLibrary. Ci sono tecniche per farlo, ma richiedono remote code execution in altro modo o un stub manuale. Il PoC sceglie la via semplice che nella stragrande maggioranza di casi va bene.

  * `lpParameter = mem`: l’indirizzo nel remote process che verrà passato come parametro a LoadLibraryA. Il thread inizierà eseguendo `LoadLibraryA(mem)`. Quindi tenterà di caricare la DLL dal percorso puntato da `mem` (nel *suo* processo).

  * `dwCreationFlags = 0`: nessuna flag, quindi il thread remoto parte subito (immediatamente in stato running).

  * `lpThreadId = NULL`: non ci interessa l’ID, quindi passiamo null.

* Se `CreateRemoteThread` restituisce NULL, c’è un errore (ad esempio mancanza di privilegio, o target process terminato prematuramente, ecc.). In tal caso, lancia eccezione con GetLastError.

  * Possibili errori: se l’indirizzo di start è invalido (in remoto, se non coincide con la giusta LoadLibrary, potrebbe scatenare un errore di accesso, ma CreateRemoteThread di per sé potrebbe ancora restituire un handle, poi il thread crasherebbe e subito terminerebbe. Quindi magari non vedresti errore qui, ma il WaitForSingleObject restituirebbe immediatamente e successiva logica di check in main capirebbe che injection è fallita).
  * Un errore immediato di CreateRemoteThread potrebbe essere dovuto a DEP (Data Execution Prevention) se quell’indirizzo non è eseguibile – ma LoadLibraryA risiede in un modulo eseguibile, quindi no. Oppure se il processo è protetto (ci sono processi PPL in cui CreateRemoteThread fallisce con accesso negato). Taskmgr in genere non è PPL, dunque ok.

* `thread` è l’handle del thread creato nel processo remoto. Il PoC lo chiude poi con `CloseHandle(thread)` (gestito in defer) dopo l’uso.

* `WaitForSingleObject(thread, INFINITE)` sospende il nostro thread finché il thread remoto non termina. In altre parole, aspettiamo che `LoadLibraryA` finisca. `LoadLibraryA` finirà quando la DLL è stata caricata:

  * LoadLibraryA carica la DLL (mappa il file in memoria nel processo remoto, risolve import, esegue la DLLMain con DLL\_PROCESS\_ATTACH nel contesto del thread chiamante).
  * Se la DLLMain non crea altri thread o non indica di non finire, il LoadLibraryA restituirà l’HMODULE della DLL caricata. A quel punto il thread remoto termina restituendo quell’HMODULE come exit code del thread (valore che potremmo ottenere con GetExitCodeThread se volessimo).
  * Nel nostro PoC, la DLL `MollyBus.dll` conterrà presumibilmente il codice che avvia il finto AV (ad esempio potrebbe inizializzare il WSC registration o segnalare qualcosa via IPC). Dal codice si evince che c’è una struttura di IPC e che dopo injection il main aspetta che `ipc->finished` venga settato, il che implica che la DLL, dopo essersi caricata, comunica col processo loader attraverso una memoria condivisa (InterProcessCommunication) e alla fine imposta `finished` e `success`. Quindi la DLL *non* termina il processo, ma farà in modo di segnalare completamento.
  * Il WaitForSingleObject con INFINITE qui attende solo la fine di LoadLibrary (che coincide con la fine di DllMain iniziale). Importante: se la DLL spawna un thread proprio in DllMain e ritorna subito, LoadLibrary finisce e thread remoto termina, ma la DLL può aver lasciato thread in esecuzione nel processo (ad es. per monitorare qualcosa in background). Questo è comune per persistenti code injection: la DLL una volta caricata, crea un thread che rimane attivo (per esempio, potrebbe tenere registrato lo stato WSC, rispondere a eventi, ecc.). Il PoC non mostra qui il codice DLL, ma l’InterProcessCommunication suggerisce che la DLL segnalerà quando ha finito le operazioni, dopodiché il loader terminerà l’intero processo remotamente.
  * Quindi, WaitForSingleObject assicura solo che la DLL sia caricata correttamente (non che il suo lavoro sia completato). Avremmo potuto anche non aspettare, ma aspettare evita di tentare subito di liberare la memoria (già gestito col defer come detto) e soprattutto, nel main, sanno dopo Wait che injection iniziale è conclusa.
  * L’handle thread remoto poi viene chiuso con `CloseHandle(thread)` deallocando la struttura del thread nel nostro processo (il thread nel remoto è terminato quindi l’handle serve solo a noi).

**Dettagli tecnici:**

* L’uso di `LoadLibraryA` come thread start routine è un trucco consolidato per injection semplice. Alternativa sarebbe scrivere direttamente uno stub assembly nel processo che chiama LoadLibrary. Ma delegarlo a Kernel32 è più semplice.
* L’assunzione dell’indirizzo è come già detto potenzialmente rischiosa su sistemi con ASLR diversificato, ma in pratica regge.
* Se la DLL ha dipendenze, LoadLibrary le caricherà pure (nel contesto remoto).
* Il `WaitForSingleObject` senza Timeout (INFINITE) significa che se per qualche ragione il thread dovesse non finire mai, ci bloccheremmo. In teoria, LoadLibraryA dovrebbe finire sempre, a meno di deadlock in DllMain (es: se DllMain va in sleep infinito, il LoadLibrary non ritorna finché quell’esecuzione iniziale non termina – e DllMain viene eseguito nello stesso thread che ha chiamato LoadLibrary, cioè il thread remoto. Best practice impone che DllMain sia veloce e non bloccante. Se la nostra DLL violatesse, il loader rimarrebbe appeso su Wait).
* Dopo Wait, non viene fatto `ResumeThread` sul thread principale di Taskmgr, quindi come detto, Taskmgr rimane sospeso all’infinito. Il processo però ora ha almeno un thread attivo (il thread remoto è finito, ma la DLL potrebbe aver avviato un thread dedicato se così progettata). Se la DLL non avvia thread, allora il processo inietatto in realtà non sta eseguendo codice attivamente (ha solo main thread sospeso). Però se la DLL ha operazioni da fare, avrà dovuto creare qualcosa. Forse la DLL setta lo stato WSC e poi semplicemente segnala successo e finisce? Potrebbe essere, dopodiché quell’intero processo è un dummy che non fa niente. In tale caso, potrebbe essere terminato subito. Ma vediamo dal main: `wait_for_finish(ipc)` attende che `ipc->finished` sia true. Chi setta ipc->finished = true? Probabilmente la DLL quando ha completato le operazioni di registro WSC. Una volta finished, il main legge `ipc->success` e lo logga, poi chiama `TerminateProcess(process, 0)` sul handle, terminando Taskmgr e quindi scaricando la DLL. Quindi in effetti, il PoC potrebbe terminare il processo iniettato abbastanza presto, non mantenerlo vivo per lungo tempo. Ciò dipende se vogliono solo dimostrare la registrazione temporanea o mantenerla.
* Tuttavia, se vogliono far credere a Windows di avere un AV, quell’AV dovrebbe stare in esecuzione costantemente. Se terminano il processo subito, WSC vedrebbe che l’AV non è in esecuzione (forse WSC manterrebbe lo stato per un po’, ma potrebbe poi dire "not reporting"). Forse ipotizzano di tenerlo attivo il più possibile.
* Guardando la logica: main chiama wait\_for\_finish, che polla la flag in shared memory. Se la DLL volesse mantenersi attiva, potrebbe non settare finished finché l’utente non chiede di terminare. Il nome `finished` fa pensare alla condizione di completamento. Forse il design è: rimani registrato per un certo tempo o finché utente preme disattiva. Non completamente chiaro senza la DLL code, ma possiamo dire che in PoC probabilmente si auto-termina dopo aver mostrato successo (il main fa system("pause") per far vedere output). Dunque è possibile che la persistenza sia più dimostrativa che reale: se termina, al prossimo riavvio via schedule rifà registrazione e ritermina.

**Sicurezza:** Creare thread remoto è un comportamento altamente rilevabile. Tools come Windows Defender ATP, EDR vari, hanno hooking su CreateRemoteThread per capire se un processo sta iniettando in un altro. In questo caso, come attaccante, stiamo iniettando in un processo figlio che noi stessi abbiamo creato, il che è un po’ meno sospetto di iniettare in un processo esistente di un’altra applicazione. Comunque, rimane un pattern noto.

* Il fatto che il thread esegua LoadLibrary, quindi la DLL verrà caricata con un Digital Signature magari mancante (la nostra DLL dubito sia firmata) dentro un processo di sistema, potrebbe far scattare controlli di integrità (ad esempio, alcuni antivirus monitorano moduli caricati in processi sensibili come explorer, csrss, etc., e se vedono moduli non Microsoft potrebbero segnalare). Taskmgr non è protetto come process, però è strano se improvvisamente ha una DLL di nome "MollyBus.dll" caricata. Un analista che guardasse con Process Explorer vedrebbe Taskmgr.exe con quell’iniettata.
* Inoltre, se la DLL fa cose malevole, avendola caricata in Taskmgr potrebbe confondere l’utente su quale processo sta realmente facendo danni (Task Manager di solito non apre rete, se la DLL aprisse socket, sarebbe insolito).
* In generale, injection in processi affidabili è fatto per **mascherare** le azioni ed eventualmente aggirare restrizioni (il processo iniettato potrebbe avere accesso a risorse che altrimenti il malware non ha, oppure evitare che l’utente termini il malware confondendolo con un processo legittimo).
* In questo PoC, lo scopo principale dell’iniezione sembra essere: eseguire il codice di registrazione WSC in un processo separato (forse perché quell’interfaccia COM WSC potrebbe dover essere chiamata da un processo isolato? Non credo, poteva farlo dal loader stesso. Oppure per simulare la presenza di un processo AV separato dal loader).
* Un motivo potrebbe essere: Windows Security Center aspetta di vedere un processo con nome o firma particolari? Ma passando il path sbagliato in Register, non credo. Forse volevano semplicemente spostare la logica WSC in una DLL per modulare il progetto (il loader rimane generico, la DLL contiene la parte di integrazione).

### Terminazione e pulizia (nel main chiamante)

Anche se la domanda non lo chiede espressamente, per completezza vediamo come il processo chiamante (loader) conclude le operazioni dopo l’iniezione, perché coinvolge API di terminazione:

Nel `main.cpp`:

```cpp
const auto process = load_MollyBus();
defer->void {
    TerminateProcess(process, 0);
};
wait_for_finish(ipc);
process_autorun(config);
banner(config);
```

* `load_MollyBus()` chiama `inject()` e ritorna l’handle `pi.hProcess` del processo iniettato (Taskmgr.exe). Lo memorizziamo in `process`. Immediatamente viene registrata un’azione differita: `TerminateProcess(process, 0)` da eseguire alla fine. Questo assicura che *qualunque cosa accada*, quando `main` va a termine, chiude il processo figlio (evitando di lasciare in giro Taskmgr iniettato). `TerminateProcess` è una chiamata immediata (non attende che i thread finiscano, kill forzato) con exit code 0.

* `wait_for_finish(ipc)` entra in un loop che attende che la memoria condivisa (`ipc`) segni `finished = true`. La condivisione `ipc` è ottenuta prima come `InterProcessCommunication ipc(sharedMemName, mode)` e la DLL presumibilmente ha accesso a questa stessa area (forse aprendo la shared memory mapping). Finché `ipc->finished` rimane false, fa sleep 500ms. Quando diventa true, logga `success` field. Questo è il modo in cui la DLL può comunicare esito. Il main thread quindi sa quando l’azione principale (registrazione WSC) è conclusa dentro la DLL.

* Dopo finito, esegue `process_autorun(config)`: se lo state era ON, chiamerà `add_to_autorun()` come visto, aggiungendo il task pianificato (così dal prossimo riavvio l’intero meccanismo riparte). Se era OFF, rimuove il task se c’era.

* `banner(config)` stampa un messaggio di ringraziamento e nel caso utente (non from\_autorun) fa `system("pause")` per attendere input, poi main finisce, eseguendo il defer che termina il processo figlio.

Quindi, la vita del processo iniettato è legata alla durata del loader *a meno che* la flag finished venga settata subito. Se per ipotesi finished venisse settata quasi immediatamente, il loader allora killerebbe subito il processo figlio. Ciò potrebbe essere troppo rapido: magari WSC vedrebbe comparire e scomparire l’AV in un lampo. Probabilmente, durante test, avranno visto che basta anche un attimo per registrarsi.

Volendo mantenere l’AV attivo indefinitamente, non avrebbero dovuto terminare il processo. Il design pare più oriented a test: far partire, registrare, e poi se utente chiude l’app, si pulisce (compresa persistenza per rifarlo al login successivo). Forse per un PoC va bene, ma un attaccante reale lo terrebbe residente.

**Considerazioni finali su iniezione:** L’iniezione qui è usata come veicolo per eseguire la logica di registrazione WSC in un processo separato (la DLL injection di per sé non era strettamente necessaria per il concetto di fake AV – si poteva fare tutto nel exe loader). Ma serve a far apparire un “processo AV” distinto? In una vera soluzione, il prodotto antivirus avrebbe un processo service, e loro qui ne simulano uno usando Taskmgr + DLL. Quindi è realistico: WSC adesso vede un prodotto registrato, e potenzialmente potrebbe monitorare se il processo indicato è in esecuzione. Non so se WSC controlla il *pathToSignedProductExe* passato in Register per vedere se un processo con quel path gira. Se lo fa, allora passare come path un URL è ovviamente sbagliato; se avessero passato qui come primo param in Register il path di Taskmgr o un loro binario, WSC si aspetterebbe che quel binario sia in esecuzione, altrimenti potrebbe dire "not running". L’API pubblica WSC di Windows 7/8 forniva lo stato "product on/off" e se non on, segnalava. Qui con COM privato non so.
In ogni caso, l’approccio injection consente di avere un processo con la DLL attiva, che potrebbe periodicamente invocare `UpdateStatus` per aggiornare definizioni, ecc., se volessimo estendere.

---

## Conclusioni e note sulla sicurezza

Abbiamo esaminato in dettaglio come il PoC **MollyBus**:

* Si registra come antivirus presso Windows Security Center usando interfacce COM non documentate (`IWscAVStatus`), bypassando i controlli standard e potenzialmente disabilitando Windows Defender.
* Installa una persistenza tramite Task Scheduler che garantisce l’esecuzione automatica e elevata del loader ad ogni logon.
* Inietta una DLL nel processo di Task Manager, sfruttando chiamate di debug e memory injection per eseguire codice (la registrazione al WSC) in un processo separato.

Dal punto di vista di un sviluppatore o ricercatore, questo PoC offre uno *spaccato di tecniche tipiche da malware*:

* **Abuso di API private/undocumented:** l’uso di IWscAVStatus mostra come, se si scoprono i giusti GUID e si hanno i privilegi, si possano effettuare operazioni altrimenti riservate. Questo evidenzia che la sicurezza per obscurity (API nascoste) non è robusta se un attaccante determinato può reverse-engineerarle.
* **Persistenza a livello di sistema:** la scelta del Task Scheduler è sofisticata rispetto a metodi più triviali. Un task pianificato con elevazione può passare inosservato più facilmente e resiste a logout e reboot. Inoltre, consente di attivare la minaccia *dopo* che l’utente ha effettuato accesso, potenzialmente posticipando l’esecuzione per confondersi nei normali processi di login.
* **Code Injection:** tecnica consolidata per occultare la logica nociva e aggirare certe difese. Anche se in questo caso l’iniezione è in un processo figlio controllato, le API usate (CreateRemoteThread, WriteProcessMemory) sono identiche a quelle per iniettare in un processo di terze parti. Un ricercatore può imparare come funziona questo meccanismo e quali contromisure (ad esempio, monitorare chiamate a DebugActiveProcessStop, VirtualAllocEx, etc.) potrebbero rilevarlo.

**Privilegi richiesti:** Come abbiamo ripetuto, il PoC necessita di privilegi elevati (amministrativi) per funzionare correttamente: registrare un antivirus fittizio e creare una task in \ requires admin. In un test su una VM, occorre eseguire il loader come amministratore. Se l’obbiettivo fosse comprometter un sistema con un utente standard, bisognerebbe prima ottenere privilegi via escalation locale.

**Ambiente di test:** L’ideale è provare il PoC su un Windows 10/11 non production, disabilitando temporaneamente l’AV reale (per evitare che interferisca). Si potrà osservare nel Centro Sicurezza la comparsa del “MollyBus” come antivirus. Event Viewer (sotto *Applications and Services Logs -> Microsoft -> Windows -> SecurityCenter*) potrebbe registrare eventi di cambio di stato del provider AV. Utilità di Pianificazione mostrerà il task “MollyBus”. Process Explorer mostrerà Taskmgr.exe con MollyBus.dll in memoria durante l’esecuzione.

**Comportamenti anomali delle API:**

* La COM WSC è soggetta a cambiamenti: su versioni future di Windows, quei GUID potrebbero cambiare o le funzioni potrebbero richiedere firme valide; quindi il PoC potrebbe smettere di funzionare o avere effetti ridotti (es. registrazione non presa sul serio da Defender).
* Le API di Task Scheduler sono consolidate e con pochi trabocchetti, ma bisogna ricordare che l’utente vede il task se guarda.
* Le API di iniezione usate non sfruttano alcun exploit, sono legittime. Ma vanno sincronizzate correttamente come fatto (detach debug prima di remote thread per evitare gating). Un uso scorretto di CreateRemoteThread (ad esempio se target a 32 bit vs 64 bit mismatch, qui non accade perché presumably loader e DLL sono stessi arch) potrebbe fallire.

**Implicazioni di sicurezza:** Dal punto di vista difensivo, questo PoC suggerisce alcune cose da monitorare:

* Registro di sistema: se appare un antivirus registrato che non corrisponde a uno noto (nome strano, percorso strano), è sospetto. Difendersi è difficile perché l’API è di sistema, ma un EDR potrebbe controllare se un processo non firmato sta chiamando CoCreateInstance di quei GUID.
* Task Scheduler: implementare controlli che avvisino se vengono creati task con nomi inconsueti o in posizioni inusuali, oppure se un processo utente crea un task runLevel highest (operazione che in ambienti gestiti si può loggare via Auditing).
* Injection: l’accoppiata DebugActiveProcessStop + CreateRemoteThread è rilevabile. Alcuni prodotti anti-malware user-mode hooking potrebbero bloccare CreateRemoteThread verso processi protetti. In effetti, Windows Defender stesso (se non disabilitato) potrebbe rilevare il pattern e terminare il nostro loader prima che completi l’injection (in un test va considerato).

**MollyBus PoC** illustra un attacco composto in più fasi: *disabilitazione difese* (falsa registrazione AV), *persistenza*, *esecuzione arbitraria in altro processo*. Ognuna di queste fasi è stata realizzata con API legittime ma usate in modo malevolo. Speriamo che questa guida abbia fornito una comprensione approfondita di ogni passo, utile per chi studia malware o vuole capire i meccanismi interni di Windows sfruttati.
