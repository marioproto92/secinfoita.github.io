## Lezione 2: Ricerca dei processi iniettabili ##
### 1. Introduzione ###
Questa lezione introduce le tecniche necessarie a iniettare del codice all’interno dei processi del sistema. Il mio codice effettua un’enumerazione dei processi attivi nel sistema e verifica se si tratta di un processo iniettabile e che quindi è possibile compromettere. 

### 2. WINAPI ###
Le WINAPI utilizzate nell’enumeratore sono le seguenti: 
CreateToolhelp32Snapshot, Process32First, CloseHandle, OpenProcess e Process32Next. 
Di seguito l’analisi dettagliata delle singole API.

#### 2.1 CreateToolhelp32Snapshot #### 
Esegue un’istantanea dei processi specificati, degli heap, dei moduli e dei thread utilizzati. Nel nostro caso utilizzeremo come parametro dwFlags TH32CS_SNAPPROCESS che includerà nell’enumerazione tutti i processi di sistema. Tale API presuppone l’uso di Process32First e Process32Next per lo scroll dei processi.
```cpp
HANDLE CreateToolhelp32Snapshot(
  [in] DWORD dwFlags,
  [in] DWORD th32ProcessID
);
```
#### 2.2 Process32First ####
Recupera le informazioni sul primo processo individuato nell’istantanea del sistema (CreateToolhelp32Snapshot). Il puntatore di struttura PROCESSENTRY32 conterrà le informazioni sul processo come il nome del file eseguibile, il PID (identificatore numerico del processo) e il PID del processo padre.
```cpp
BOOL Process32First(
  [in]      HANDLE           hSnapshot,
  [in, out] LPPROCESSENTRY32 lppe
);
```
#### 2.3 CloseHandle ####
Chiude l’handle di un oggetto aperto. Nel nostro caso è essenziale per distruggere lo snapshot.
```cpp
BOOL CloseHandle(
  [in] HANDLE hObject
);
```
#### 2.4 OpenProcess ####
Apre un processo esistente mediante il suo PID. L’uso del parametro dwDesiredAccess nel  nostro caso richiede il diritto di accesso PROCESS_ALL_ACCESS: Tutti i possibili diritti di accesso per un oggetto di processo. Se l'apertura dell’oggetto avverrà con tali diritti, avremo la certezza che si tratti di un processo iniettabile.
```cpp
HANDLE OpenProcess(
  [in] DWORD dwDesiredAccess,
  [in] BOOL  bInheritHandle,
  [in] DWORD dwProcessId
);
```
#### 2.5 Process32Next ####
Diversamente da Process32First, Process32Next ci permette di recuperare le informazioni sul processo successivo registrato nell'istantanea di sistema. Anche in questo caso, l’uso del puntatore  PROCESSENTRY32 è fondamentale per accedere alle informazioni dei processi.
```cpp
BOOL Process32Next(
  [in]  HANDLE           hSnapshot,
  [out] LPPROCESSENTRY32 lppe
);
```
### 3. Costruiamo le strutture ###
Per prima cosa è necessario costruire le struct e i vector necessarie a contenere le informazioni legate ai processi iniettabili ricavate dall’enumerazione.
```cpp
typedef struct process_info {
	DWORD PID;
	std::wstring wszProcessName = L"";
	BOOL injectableProcess = FALSE;
} PROCESS_INFO, * LPPROCESS_INFO;

typedef std::vector<PROCESS_INFO> PROCESS_VECTOR;
```
La struttura conterrà l’identificativo del processo (PID), il nome del processo è un valore booleano che identifica se un processo è iniettabile.
### 4. Cerchiamo i processi iniettabili ###
Per prima cosa catturiamo un’istantanea dei processi di sistema con l’API CreateToolhelp32Snapshot.
```cpp
HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
if (hSnapShot == NULL) return 0;
```
Da notare l’uso del parametro TH32CS_SNAPPROCESS che ci permetterà di includere nell’enumerazione anche i processi sistema.
Prima di richiamare l’API Process32First è necessario inizializzare un PROCESSENTRY32 che conterrà le informazioni sui processi.
```cpp
PROCESSENTRY32 pe32;
pe32.dwSize = sizeof(PROCESSENTRY32);
```
Ora tramite Process32First otteniamo il primo processo nell’istantanea.
```cpp
if (!Process32First(hSnapShot, &pe32))
	{
		CloseHandle(hSnapShot);
		return 0;
	}
```
Se non vi saranno errori con l’API, il processo di enumerazione continuerà con lo scroll dello snapshot attraverso un’iterazione post-condizionale che terminerà solo quando tutti i processi presenti nello snap saranno stati elaborati.
```cpp
do
	{
		PROCESS_INFO pi;
		pi.PID = pe32.th32ProcessID;
		pi.wszProcessName = pe32.szExeFile;

		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
		if (hProcess != NULL)
		{
			pi.injectableProcess = TRUE;
			CloseHandle(hProcess);

			lpaProcessInfo->push_back(pi);
		}

	} while (Process32Next(hSnapShot, &pe32));
  ```
### 5. Avviamo il codice ###
Ora richiamiamo nel main la funzione creata:
```cpp
int main()
{
	PROCESS_VECTOR pvProcesses; //Inizializziamo il vettore che conterrà le informazioni relative ai soli processi iniettabili.
	FindInjectableProcesses(&pvProcesses); // Richiamiamo la nostra funzione
	return 0;
}
```
### 6. Output ###
Come potete vedere dal seguente screen, nella mia macchina ci sono 73 processi iniettabili. 
![image](https://user-images.githubusercontent.com/85390166/181889489-75a3ec76-2eee-4de3-9460-fe921258d7e8.png)
Tali processi potrebbero per esempio essere utilizzati per l’iniezione di librerie malevole (DLL Injection) o di uno shellcode, permettendo quindi al malware di infettare il sistema e ottenere, per esempio, il privilege escalation.
