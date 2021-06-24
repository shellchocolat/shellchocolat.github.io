
__Shikata Ga Nai__ est un encodeur très populaire dans le monde des pentesters. Il a la particularité d'être polymorphique, ce qui signifie qu'il existe plusieurs manières d'obtenir le même résultat encodé. 

Un antivirus fonctionne par signatures, mais si le code est toujours différent, il n'est pas possible de définir de signature valable. C'est pourquoi les encodeurs polymorphiques sont d'une grande utilité pour encoder du code malveillant.

Je vais tenter de présenter dans cet article la beauté de l'encodeur __Shikata Ga Nai__, mais également comment il est possible de le détecter, et de le modifier.

Pour comprendre le fonctionnement d'un encodeur, l'idéal est d'avoir quelque chose à encoder. Le code que je vais encoder ne contient que des __nop__ (0x90). Je le code sous une machine linux car la manière la plus rapide d'encoder en utilisant __Shikata Ga Nai__ est d'utiliser __msfvenom__ (pré-installé sur __Kali Linux__).

Le code que je vais encoder est:

```
global _start
section .text

_start:
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
```

Pour le compiler, je vais utiliser __nasm__ comme suit:


```
nasm code.asm -o bytecode.bin
```

Et pour l'encoder en utilisant l'encodeur __Shikata Ga Nai__ via __msfvenom__, je tape la commande suivante:

```
cat bytecode.bin | msfvenom -p - -a x86 --platform win -e x86/shikata_ga_nai -f hex
```

J'ai dit que l'encodeur __Shikata Ga Nai__ était polymorphique, voyons cela. Je vais générer plusieurs fois mon code encodé et regarder ce que cela donne. Le résultat est présenté dans la liste ci-dessous:

* DAC1D97424F45A33C9B81E582E88B10483C204314213035C4BCC7DF0FB80EE606B309E101CA10F

* B8ECABC3ECD9C4D97424F45D29C9B104314512034512830157211949383672F9A9A7E369595793

* B89B83585ADBC5D97424F45A31C9B10431421283EAFC03D98DBAAF4D01AAC0FDB25B706D22CBE1

* DBD3D97424F4B8440727C55B33C9B10483EBFC314313030714C530178A992B873B09DB37ABBA4C

* BA0F6F1590D9CED97424F45D31C9B10431551203551283CA6BF76544E36715F494188664048837

Effectivement quand on regarde les bytecodes générés, on se rend bien compte qu'ils ne se ressemblent pas. C'est donc extrêmement difficile de pouvoir faire une signature valable pour un antivirus.

Je me permet de remettre la liste ci-dessus en y ajoutant un peu de couleur ...:

* DAC1<span style="color:red">D97424F4</span>5A33C9B81E582E88B10483C204314213035C4BCC7DF0FB80EE606B309E101CA10F

* B8ECABC3ECD9C4<span style="color:red">D97424F4</span>5D29C9B104314512034512830157211949383672F9A9A7E369595793

* B89B83585ADBC5<span style="color:red">D97424F4</span>5A31C9B10431421283EAFC03D98DBAAF4D01AAC0FDB25B706D22CBE1

* DBD3<span style="color:red">D97424F4</span>B8440727C55B33C9B10483EBFC314313030714C530178A992B873B09DB37ABBA4C

* BA0F6F1590D9CE<span style="color:red">D97424F4</span>5D31C9B10431551203551283CA6BF76544E36715F494188664048837

Félicitation, vous venez de trouver le point fixe de __Shikata Ga Nai__ (__D97424F4__) !!

Par point fixe, j'entend une série d'opcodes qui se retrouvera tout le temps lorsque l'on générera du code encodé avec __Shikata Ga Nai__, peu importe la payload que l'on encode.

Essayons de comprendre l'utilité de ce point fixe. Pour cela on va désassembler le code avec __objdump__ (objdump -d bytecode_encoded.bin). On obtient le code suivant:

![image alt text](/images/encoder-shikaganai/shikataganai_disas.png)

Une chose que l'on constate de prime abord est que le code encodé est situé dans la zone __.data__. Ce qui signifie qu'elle est __RW__ (Read Write). Bon, pour l'explication, j'ai utilisé un format de sortie de __msfvenom__ comme étant __exe-small__. Msfvenom par défaut génère un exécutable avec le code encodé dans la section __.data__. Pour le rendre exécutable, il doit rendre cette section exécutable à un moment donné. Mais ce n'est pas le sujet de cet article (peut être pour un autre). Il faut juste s'en souvenir car lorsque j'analyserais dynamiquement le code encodé dans un debugger, il faudra penser à copier le code dans une section exécutable.

Bref. La seconde chose que l'on constate est que le point fixe correspond à l'instruction __fnstenv esp-0x0C__ (opcodes: __D97424F4__). Cette instruction est une instruction du __co-processeur x87__. Je vous laisse digérer cette information avant d'entrer dans les détails.

Le __processeur x86__ ne permet de traiter que des entiers. Afin de pouvoir faire du calcul en virgule flottante, il a fallu imaginer un processeur capable de faire cela. Il a alors été décidé d'ajouter un co-processeur au processeur x86. C'était alors un processeur à part entière de la famille des 8087, simplifié en x87. Il était donc positionné à côté du processeur x86. On parlait donc de co-processeur. Le terme est resté bien que maintenant le x86 et le x87 ait fusionné.

Néanmoins il est toujours d'actualité que chacun des "2 processeurs" aient leurs propres jeu d'instructions, avec leurs propres stacks et leurs propres registres. 

Plutôt que de parler de __co-processeur x87__, on parle le plus souvent de __FPU__ (Floating Point Unit) et l'on comprend de suite de quoi il s'agit. En quoi cela concerne __Shikata Ga Nai__?

Tout encodeur/décodeur a besoin de connaitre l'espace des adresses qui contient du code à encoder/décoder. Dans le cas de __Shikata Ga Nai__ qui a été conçu pour fonctionner avec des exploits qui n'ont pas d'adresses fixes et juste des adresses relatives, le meilleur moyen de récupérer les adresses et d'utiliser le pointeur d'instruction (__eip__). En effet l'__eip__ pointe sur l'instruction en cours. Ainsi on peut déterminer un offset par rapport à l'__eip__ pour connaitre la première adresse à décoder.

Seulement il n'est pas possible de faire un __push eip__ ou un __mov [eax], eip__. Il faut donc trouver une astuce pour récupérer l'__eip__. L'instruction __fnstenv__ permet de sauvegarder l'environnement FPU à l'adresse spécifier dans l'opérande de destination: ici à __esp-0x0C__, on pourra récupérer l'__eip__ avec un __pop edx__ par exemple.

Avant d'aller plus loin, je vais coder un programme qui utilise le code encodé avec __Shikata Ga Nai__ (je prend le premier de liste ci-dessus). Le code utilise la fonction __VirtualAlloc()__ afin d'allouer une zone mémoire RWE (Read Write Executable). Puis je récupère le pseudo-handle du processus en cours avec la fonction __GetCurrentProcess()__, et enfin j'y copie le code de mon code encodé avec la fonction __WriteProcessMemory()__.


<details><summary><font color="red">Ici se trouve le code permettant d'exécuter le code encoder avec Shikata Ga Nai</font></summary>
<p>
```
.586
.model flat, stdcall

; kernel32.dll
GetLastError PROTO STDCALL
VirtualAlloc PROTO :DWORD,:DWORD,:DWORD,:DWORD
GetCurrentProcess PROTO STDCALL
WriteProcessMemory PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD,:DWORD


.data
	shellcode	db 0dah,0c1h,0d9h,74h,24h,0f4h,5ah,33h,0c9h,0b8h,1eh,58h,2eh,88h,0b1h,04h,83h,0c2h,04h,31h,42h,13h,03h,5ch,4bh,0cch,7dh,0f0h,0fbh,80h,0eeh,60h,6bh,30h,9eh,10h,1ch,0a1h,0fh, 0

.data?
 	hProcess 	dd ?
 	baseAddr 	dd ?

.code

Start PROC

	push 	40h ; PAGE_EXECUTE_READWRITE
	push 	1000h ; MEM_COMMIT
	push 	100h
	push 	0
	call 	VirtualAlloc
	mov 	[baseAddr], eax

	call 	GetCurrentProcess
	mov 	[hProcess], eax

	push 	0
	push 	sizeof shellcode
	push 	offset shellcode
	push 	baseAddr
	push  	hProcess
	call 	WriteProcessMemory

	jmp 	baseAddr

Start ENDP
END
```
</p>
</details>


Je peux maintenant débugger le code encodé facilement. Le code du décodeur __Shikata Ga Nai__ est présenté ci-dessous:

```
fcmovb 	st(0), st(1)
fnstenv [esp-0x0C]
pop 	edx
xor	ecx, ecx
mov 	eax, 882E581E
mov 	cl, 4
add	edx, 4
xor 	[edx+0x13], eax
add	ebx, [ecx*2 + ebx - 0x34]
jge	0014000C
sti
sub 	dh, 0x60
blablablabla
```

Ok, le code n'a pas l'air évident de prime abord, mais n'oublions pas qu'il y a du code encodé ainsi que le décodeur. Une autre particularité de __Shikata Ga Nai__ est qu'une partie du décodeur est lui-même encodé. On verra ça un peu plus loin lorsque l'on regardera les instructions les unes à la suite des autres.

Revenons sur le __FPU__ (co-processeur qui permet de faire du calcul en virgule flottante). Afin de pouvoir utiliser l'instruction __fnstenv__ (permet de sauvegarder l'environnement FPU et notamment l'__eip__), il faut d'abord l'utiliser. C'est pour ça que le décodeur commence par l'instruction __fcmovb st(0), st(1)__.

<span style="color:cyan">Première instruction:</span> L'instruction __fcmovb st(0, st(1)__ est une instruction __FPU__ qui effectue un __mov__ du registre __st(1)__ vers le registre __st(0)__ si le flag __CF__ (Carry Flag) est mis à __1__. En soit la condition n'est pas importante, mais c'est quand même cool de savoir qu'il existe des __mov conditionnels__. Bref. Les registres __FPU__ se noment __st__ (pour Top Stack il me semble) et il en existe __8__ (st(0) ... st(7)) et ils servent également de stack, c'est-à-dire que l'on peut effectuer des __push__. On peut retenir pour la culture, qu'ils sont cycliques, dans le sens où si l'on __push__ 9 fois successivement, on finit par écraser __st(0)__. Bref, encore.

Pour être clair, le fait de faire un __fcmovb st(0), st(1)__ permet d'utiliser le __FPU__ est donc d'avoir un environnement à sauvegarder grâce à __fnstenv__.

Regardons l'état des registres avant l'exécution du __fcmovb__:

![image alt text](/images/encoder-shikaganai/fpu_stack_before_fcmovb.png)

Et maintenant, regardons l'état des registres après l'exécution du __fcmovb__:

![image alt text](/images/encoder-shikaganai/fpu_stack_after_fcmovb.png)

On voit qu'il y a effectivement eu une action sur la stack FPU, mais on dirait que l'on a mis une erreur dans __st(0)__. Cela ne pose pas de problème car l'idée était simplement d'utiliser le FPU pour pouvoir sauvegarder l'environnement FPU et donc récupérer l'__eip__. Je propose une petite modification inédite pour ceux qui lise cet article et qui permet de ne pas générer d'erreur (ce n'est pas utile, mais autant être propre ...). Utiliser le mnémonique __ftst__ plutôt que __fcmovb__:

```
ftst
fnstenv [esp-0x0C]
```

D'une part, cela modifie la signature de la payload et en plus c'est du code propre ! L'instruction __ftst__ permet de comparer la valeur situé à __st(0)__ avec __0,0__ (virgule flottante, hein!).

<span style="color:cyan">Deuxième instruction:</span> L'instruction __fnstenv [esp-0x0C]__ sauvegarde l'environnement et donc l'eip sur la stack à l'offset 0x0C. En réalité, ce n'est pas directement l'__eip__ qui est sauvegardé, mais l'adresse à laquelle la première instruction FPU à eu lieu (instruction précédente du coup: __fcmovb__). Regardons le code dans le debugger pour cela:

![image alt text](/images/encoder-shikaganai/stack_after_fnstenv.png)

On voit bien que l'__esp__ pointe alors vers l'adresse de la première instruction lié au FPU. 

Juste une chose à préciser; vous pourrez constater que mes adresses dans le debugger sont toujours différentes, c'est parce que je relance le code plusieurs fois pour m'assurer de la justesse de ce que je fais. Et comme je laisse __VirtualAlloc()__ décider de l'endroit où sera allouer ma zone mémoire, ce n'est donc jamais la même. C'était une parenthèse pour ceux qui regardent les screenshots :p

<span style="color:cyan">Troisième instruction:</span> Bon, pour le __pop edx__, on comprend qu'on récupère l'__eip__ (enfin, pas vraiment l'eip, on l'a compris maintenant) sur la stack dans le registre __edx__.

<span style="color:cyan">Quatrième instruction:</span> Le __xor ecx, ecx__ permet de mettre __0__ dans __ecx__. Ce registre servira de compteur pour une boucle. Cette boucle n'apparait pas clairement dans le code pour le moment car c'est cette partie du décodeur qui est encodée.

<span style="color:cyan">Cinquième instruction:</span> Le __mov eax, 882E581E__ permet de mettre la valeur __882E581E__ dans le registre __eax__. Cette valeur est la clef de déchiffrement du premier "block" de la payload (ici des __0x90__ pour rappel).

<span style="color:cyan">Sizième instruction:</span> Le __mov cl, 4__ permet de mettre le registre __cl__ à 4. Cette valeur est le nombre de "block" à déchiffrer. Elle est fixée par la taille de la payload à décoder.  Ma payload faisait __12__ nop. Un __nop__ est codé sur un octet: 0x90. Le décodeur __Shikata Ga Nai__  décode par "block" de __4__ octets. Il y a donc __3__ "blocks" à décoder (12/4=3). Mais l'instruction qui fait la boucle (que l'on n'a pas encore vu) s'arrète de boucler lorsque ecx est à 0. Il faut donc ajouter une unité pour être sûr de tout décoder. Si ce n'est pas clair, debugger et ce sera limpide.

<span style="color:cyan">Septième instruction:</span> Le __add edx, 4__ permet d'ajouter __4__ à l'__eip__ (enfin, le début du décodeur, pas vraiment l'eip, on se comprend, hein?).

<span style="color:cyan">Huitième instruction:</span> On arrive au déchiffrement. Il s'agit d'un __xor [edx+0x13], eax__. Il s'agit d'un simple __xor__ ! On se souvient que la clef de chiffrement est dans __eax__ (cinquième instruction). Le point intéressant est que __edx+0x13__ pointe au milieu d'une instruction. Regardez la figure suivante:

![image alt text](/images/encoder-shikaganai/xor_0.png)


(attention aux adresses, elle diffèrent entre les screenshots). On voit que __edx__ est à __00750004__. En ajoutant alors __0x13__, on obtient l'adresse __00750017__, ce qui pointe au milieu de l'instruction __add ebx, ..__ (035C4B...). C'est une technique sympa d'obfuscation. C'est-à-dire que l'instruction qui sera décodée commencera par (03: adresse 00750016). Regardons l'état du code après le premier passage de la routine de déchiffrement: 

![image alt text](/images/encoder-shikaganai/xor_1.png)

On voit que le code a bien été modifié (merci la zone mémoire RWE). On voit qu'il ne s'agit toujours pas de notre payload (qui ne contient que des nop). Il s'agit donc d'une partie du décodeur !

<span style="color:cyan">Neuvième instruction:</span> Le __add eax, [edx+0x13]__ permet de modifier le registre __eax__. Mais __eax__ contient la clef de déchiffrement ... En effet, __Shikata Ga Nai__ utilise un chiffrement __xor__ à clef multiple. Chaque tour de boucle aura alors une clef différente basé sur la clef précédente.

<span style="color:cyan">Dizième instruction:</span> C'est également une instruction qui était encodée. Une fois décodée lors du premier passage, on a obtenu un __loop 00750010__ qui permet d'effectuer une boucle en fonction de la valeur de compteur situé dans __ecx__. Cette instruction décremente ecx de 1 à chaque tour. On voit qu'elle renvoit vers __add edx, 4__, ce qui permet d'incrémenter de 4 les adresses que l'on doit déchiffrer. Une fois ecx à 0, on continu. Regardons ce qu'il se passe au niveau du code une fois que l'on a fait le second passage de la routine de déchiffrement:

![image alt text](/images/encoder-shikaganai/xor_2.png)


Yeah ! On voit les nop qui apparaissent (notre payload encodée). Ce qui veut dire que le déchiffrement fonctionne correctement. De plus, on voit qu'elle commence juste après l'instruction __loop__, ce qui veut dire qu'une fois la routine de déchiffrement finie (ecx = 0), le code continuera naturellement vers la payload.

Bon voilà, j'espère que l'encodeur __Shikata Ga Nai__ n'a plus de secret pour vous!

Vous imaginez déjà qu'il est possible de le modifier tout en gardant ses spécificités. On peut enlever tout ce qui touche au __FPU__ par exemple (fcmovb et fnstenv) afin d'avoir des instructions plus classique et qui ne rentre pas dans la convention Shikata Ga Nai. Comme il ne s'agit que de récuperer une adresse de référence, on peut trouver d'autres techniques, ca existe !  C'était le seul point fixe de cet encodeur qui pouvait servir de signature, et je vous évoque la possibilité de l'enlever facilement ... pour le bien de l'humanité bien sûr.

En guise de conlusion, c'est un très bel encodeur, qui utilise pas mal de __hacks__ d'assembleur. Il est très court, 10 instructions, ce qui est top pour ne pas ajouter de poids à notre payload. De plus, il ne contient pas de null bytes. Enfin, que demander de plus?
