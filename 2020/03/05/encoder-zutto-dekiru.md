
__Zutto Dekiru__ est un encodeur disponible dans metasploit. Il peut être facilement utilisé grâce à __msfvenom__. 

Cet article fait suite à celui sur l'encodeur __Shikata Ga Nai__ (https://dokyx.fr/blog/usljfhsl_encoder_shikataganai/)

Tout comme __Shikata Ga Nai__, l'encodeur __Zutto Dekiru__ est polymorphique. Je vais tenter de vous le présenter correctement, et si vous avez lu l'article concernant __Shikata Ga Nai__, vous devriez y trouver pas mal de similarités. 

De la même manière que pour __Shikata Ga Nai__, je vais avoir besoin d'une payload à encoder afin de pouvoir comprendre le fonctionnement de __Zutto Dekiru__. Je vais prendre la payload suivante (codée en assembleur, compilée avec __nasm__ sous __Kali Linux__).

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

Pour le compiler, j'utilise donc __nasm__ comme suit:

```
nasm code.asm -o bytecode.bin
```

Et pour l'encoder en utilisant l'encodeur __Zutto Dekiru__ via __msfvenom__, je tape la commande suivante:

```
cat bytecode.bin | msfvenom -p - -a x64 --platform win -e x64/zutto_dekiru -f hex
```

Une chose à noter avant de poursuivre: le code sera en 64 bits contrairement à celui présenté pour __Shikata Ga Nai__ qui était en 32 bits. Ceci étant dit, c'est parti!

Tout comme __Shikata Ga Nai__, __Zutto Dekiru__ est polymorphique. Voyons cela en générant plusieurs code encodé de ma payload:

* DDC04831C054B002596681E150F6480FAE0149BBE4B55E307E0CFEB84C8B610848FFC84D315CC42D4885C075F37425CEA0EE9C6E287425CEA0CE93B728

* DAD4544D31C95B6681E390F341B10248BD2DEFBC053C3FF0E5480FAE034C8B730849FFC94B316CCE2E4D85C975F3BD7F2C95ACAF6075BD7F2C95777758A5

* 544D31FF5DD9C06681E5C0F641B702480FAE450048BFB27B27637181D11F4883C5084C8B650049FFCF4B317CFC2E4D85FF75F322EBB7F3E111418F22EBB7F331C7FD86

* 49BDC71C99BBD261FAA64989E24D31C9664181E240F5DBD7490FAE0241B1024D8B7A0849FFC94F316CCF1A4D85C975F3578C092B42F16A36578C092B2F27B4EF

* 544831F6DDC15A6681E2F0F840B602480FAE0248B80C88AE3C2E2319634C8B6A0848FFCE493144F52A4885F675F39C183EACBEB389F39C183EACBCDAAE2A

Effectivement quand on regarde les bytecodes générés, on se rend bien compte qu'ils ne se ressemblent pas. C'est donc extrêmement difficile de pouvoir faire une signature valable pour un antivirus ...

Je me permet de remettre la liste ci-dessus en y ajoutant un peu de couleur ...:

* DDC04831C054B002596681E150F648<span style="color:red">0FAE</span>0149BBE4B55E307E0CFEB84C8B610848FFC84D315CC42D4885C075F37425CEA0EE9C6E287425CEA0CE93B728

* DAD4544D31C95B6681E390F341B10248BD2DEFBC053C3FF0E548<span style="color:red">0FAE</span>034C8B730849FFC94B316CCE2E4D85C975F3BD7F2C95ACAF6075BD7F2C95777758A5

* 544D31FF5DD9C06681E5C0F641B70248<span style="color:red">0FAE</span>450048BFB27B27637181D11F4883C5084C8B650049FFCF4B317CFC2E4D85FF75F322EBB7F3E111418F22EBB7F331C7FD86

* 49BDC71C99BBD261FAA64989E24D31C9664181E240F5DBD749<span style="color:red">0FAE</span>0241B1024D8B7A0849FFC94F316CCF1A4D85C975F3578C092B42F16A36578C092B2F27B4EF

* 544831F6DDC15A6681E2F0F840B60248<span style="color:red">0FAE</span>0248B80C88AE3C2E2319634C8B6A0848FFCE493144F52A4885F675F39C183EACBEB389F39C183EACBCDAAE2A

Félicitation, vous venez de trouver le point fixe de __Zutto Dekiru__ (__0FAE__) !!

On peut le comparer au point fixe de __Shikata Ga Nai__ qui était __D97424F4__. On remarque alors qu'il est 2 fois plus petit: seulement 2 octets !

Les opcodes __0FAE__ correspondent à l'instruction __fxsave/fxsave64__ (https://www.felixcloutier.com/x86/fxsave). Ce mnémonique, tout comme __fnstenv__ (shikata ga nai), est une instruction du __FPU__. Elle permet de sauvegarder l'état du FPU, de la technologie __MMX__, les registres __XMM__ et __MXCSR__ dans une destination spécifiée par l'opérande de destination.

Je vais rapidement détailler les acronymes MMX, XMM et MXCSR (FPU déjà vu dans l'article concernant Shikata Ga Nai). Le __MMX__ (MultiMedia eXtension) permet d'effectuer des calculs sur des entiers seulement (contrairement au __FPU__). 8 registres spécifiques d'une taille de 64 bits sont définis pour cela (__MM(0) ... MM(7)__). Encore un autre jeu d'instructions existe, il s'agit du __SSE__ (il existe maintenant le SSE2, SSE3, SSSE3, SSE4.1\/4.2\/a). Le SSE est l'acronyme de Streaming SIMD Extensions. Pour utiliser ce nouveau jeu d'instructions (70 instructions supplémentaires), il a fallu de nouveaux registres. 8 nouveaux registres de 128 bits + 1 de 32 bits ont donc été mis en place (merci la miniaturisation des processeurs !!). Ces registres sont les __XMM__ et le  __MXCSR__. Les 8 registres XMM vont de __XMM(0 ... XMM(7)__ et ont 128 bits. Quant au registre __MXCSR__, il n'est pas directement accessible et agit comme les __flags__ du processeurs x86. Il permet de controler et donner des status suite à l'execution des  70 instructions SSE (http://softpixel.com/~cwright/programming/simd/sse.php).

Bref. L'utilité de l'instruction __fxsave__ est de récupérer __rip__. Enfin ... comme pour __Shikata Ga Nai__, ce n'est pas vraiment __rip__ qui est récupéré mais l'adresse de la première instruction FPU utilisée, ce qui permet d'avoir une adresse de référence pour décoder la payload correctement. __A noter que sur du x64, il est possible de récupérer **rip** directement__ (ce qui n'était pas le cas pour du x86!). On peut par exemple utiliser:

```
lea rax, [rip]
```

Ce qui peut laisser songeur quant à l'utilité d'utiliser les instructions __FPU__ pour obtenir une adresse de référence sur du x64 ... A noter cependant que l'instruction précédente est convertie en __488D0500000000__: présence de __null bytes__.

Avant d'aller plus loin, je vais coder un programme qui utilise le code précédement encodé avec __Zutto Dekiru__ (je prend le premier de liste ci-dessus). Le code utilise la fonction __VirtualAlloc()__ afin d'allouer une zone mémoire RWE (Read Write Executable). Puis je récupère le pseudo-handle du processus en cours avec la fonction __GetCurrentProcess()__, et enfin j'y copie le code de mon code encodé avec la fonction __WriteProcessMemory()__ (tout pareil que lorsque que j'ai traité de __Shikata Ga Nai__ hormis que le code est maintenant x64).


<details><summary><font color="red">Ici se trouve le code permettant d'exécuter le code encoder avec Zutto Dekiru</font></summary>
<p>
```
; kernel32.dll
GetLastError PROTO STDCALL
ExitProcess PROTO STDCALL :DWORD
VirtualAlloc PROTO :DWORD,:DWORD,:DWORD,:DWORD
GetCurrentProcess PROTO STDCALL
WriteProcessMemory PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD,:DWORD


.data
	shellcode db 0ddh,0c0h,48h,31h,0c0h,54h,0b0h,02h,59h,66h,81h
		  db 0e1h,50h,0f6h,48h,0fh,0aeh,01h,49h,0bbh,0e4h,0b5h
		  db 5eh,30h,7eh,0ch,0feh,0b8h,4ch,8bh,61h,08h,48h,0ffh 
		  db 0c8h,4dh,31h,5ch,0c4h,2dh,48h,85h,0c0h,75h,0f3h,74h 
		  db 25h,0ceh, 0a0h, 0eeh,9ch,6eh,28h,74h, 25h,0ceh,0a0h
		  db 0ceh,93h,0b7h,28h
	EndShellcode db 0

.data?
 	hProcess QWORD ?
 	baseAddr QWORD ?

.code

Start PROC

	
	mov 	r9, 40h ; PAGE_EXECUTE_READWRITE
	mov 	r8, 1000h 
	mov 	rdx, 100h
	xor 	rcx, rcx
	call 	VirtualAlloc
	mov 	[baseAddr], rax

	call 	GetCurrentProcess
	mov 	[hProcess], rax

	mov 	rax, offset shellcode
	mov 	r9, offset EndShellcode
	sub 	r9, rax
	inc 	r9
	push 	0
	mov 	r8, offset shellcode
	mov 	rdx, baseAddr
	mov 	rcx, hProcess
	call 	WriteProcessMemory

	jmp 	baseAddr

Start ENDP
END
```
</p>
</details>

Concernant le code ci-dessus, il y a quelques modifications par rapport à celui utilisé lors de l'étude de __Shikata Ga Nai__. En effet, outre les principales caractéristiques liées aux x64, je n'ai pas pu utilisé  __sizeof__ pour calculer la  taille du shellcode à copier dans la zone mémoire RWE, car la taille était trop grande et posait un problème au compilateur ... pff.  J'ai du diviser mon shellcode et calculer la taille manuellement. Si des questions, n'hésitez pas à me contacter.

Bref. Je peux maintenant débugger le code encodé facilement. Le code du décodeur __Zutto Dekiru__ est présenté ci-dessous:

```
ffree 	st(0)
xor 	rax, rax
push	rsp
mov 	al, 2
pop 	rcx
and 	cx, 0xF650
fxsave 	[rcx]
mov 	r11, 0xB8FE0C7E305EB5E4
mov 	r12, [rcx+8]
dec 	rax
xor 	[r12 + rax\*8 + 2D], r11
test 	rax, rax
jne 	blopblop
je 	bipblip
blabla encoded blabla
```

Bon, le code ressemble vraiment à celui de __Shikata Ga Nai__. Vous devriez y voir clair si vous avez lu l'article sur __Shikata Ga Nai__. Reprenons les instructions une à une.

<span style="color:cyan">Première instruction:</span> L'instruction __ffree st(0)__ est une instruction __FPU__ qui permet d'utiliser le FPU afin de récupérer plus tard une adresse de référence, ce qui permettra de trouver les adresses contenant du code à décoder. 

<span style="color:cyan">Deuxième instruction:</span> Le __xor rax, rax__, permet de mettre le registre __rax__ à __0__. On verra par la suite (instruction 4) que celui-ci contiendra le nombre de "block" à décoder.

<span style="color:cyan">Troisième instruction:</span> Le __push rsp__ permet de sauvegarder l'adresse actuelle pointant vers la stack. Elle sera réutilisée par la suite (instruction 5) afin de récupérer l'adresse de la première instruction utilisant le FPU afin d'avoir une adresse de référence.

<span style="color:cyan">Quatrième instruction: </span> Cette instruction (__mov al, 2__) permet de mettre dans __rax__ le nombre de "blocks" à décoder. La payload que j'ai encodé faisait __12 nop__, et donc 12 bytes. Chaque "block"  à décoder fait 8 bytes. Il faut donc 2 "blocks" pour décoder la payload entière. Comme la payload ne fait que 12 bytes, il y aura un padding de 4 bytes qui auront été ajoutés. Ce padding est constitué de nop afin de ne pas influer sur le fonctionnement de la paylaod.

<span style="color:cyan">Cinquième instruction: </span> Le __pop rcx__ permet de de récupérer l'adresse du haut de la stack qui a été poussée lors de l'instruction 3. C'est donc à partir de __rcx__ que l'on trouvera une adresse de référence. Cette adresse de référence sera poussé sur la stack un peu plus loin (instruction 7) lors du __fxsave__.

Pour l'instant tout se passe grosso-modo comme pour __Shikata Ga Nai__.

<span style="color:cyan">Sizième instruction: </span> Cette instruction n'est pas présente dans __Shikata Ga Nai__. il s'agit du __and cx, 0xF650__. Cela permet d'effectuer de la place sur la stack (ne pas oublier que rcx contient alors l'adresse du haut de la stack). Cet espace sur la stack sera utilisé par l'instruction __fxsave__ afin de sauvegarder l'état FPU et les registres MM et XMM et MXCSR. 

<span style="color:cyan">Septième instruction: </span> Il s'agit du fameux __fxsave__. A-t-on vraiment besoin de dire l'utilité de cette instruction ... je pense que non. Il s'agit du coeur de __Zutto Dekiru__, et on en parle depuis le début.

<span style="color:cyan">Huitième instruction: </span> On récupère la clef de chiffrement. L'instruction __mov r11, B8FE0C7E305EB5E4__ permet de mettre la clef de chiffrement dans le registre __r11__. Oui, comme dans __Shikata Ga Nai__, il s'agit aussi d'un __xor__.

<span style="color:cyan">Neuvième instruction: </span> Là ça devient un peu intéressant. C'est là que l'on récupère l'adresse pointant vers la première instruction FPU. il s'agit du __mov r12, [rcx+8]__. On se souvient que __rcx__ pointe à l'offset où est sauvegardé l'environement FPU (instruction 6). En prenant un offset de 8 par rapport à cet offset, on récupère notre adresse de référence. Vous pouvez le vérifier en déboguant par vous-même.

<span style="color:cyan">Dizième instruction: </span> __dec eax__ permet de décrémenter __eax__ de 1. Pourquoi faire cela? On a vu à l'instruction 4 que l'on mettait 2 dans __al__ car c'était le nombre de "blocks" à décoder. En réalité, pour décoder 2 blocks, il faut mettre __al__ à 1. Il y a le block 0, puis le block 1, ce qui fait bien 2. 

<span style="color:cyan">Onzième instruction: </span> C'est là que le déchiffrement a lieu. Le __xor [r12 + rax\*8 +2D], r11__ permet de déchiffrer le contenu situé à l'adresse r12 + rax\*8 + 0x2D. Cela permet de passer au dela du mécanisme de boucle de déchiffrement.

<span style="color:cyan">Douzième/treizième/quatorzième instructions: </span> Le mécanisme de boucle est différent de celui utilisé lors de __Shikata Ga Nai__. En effet, celui-ci est visible directement alors que dans __Shikata Ga Nai__, cette partie du décodeur était encodé, ce qui ajoutait de l'obfuscation. Ce n'est pas le cas ici. La boucle est effectuée grâce à un:

```
test 	rax, rax
jne 	adresse de l'instruction 10
```

au lieu d'un:

```
loop
```

En soit, ce n'est pas un problème car dans __Shikata Ga Nai__, cette instruction était toujours présente (bien qu'encodée) et devait absolument utilisé __rcx__ comme compteur. Ici, on s'affranchit de forcément utiliser __rcx__ comme compte, ce qui laisse des degrés de liberté quant aux registres utilisés.

De plus, en regardant cette boucle de déchiffrement, on se rend compte que la clef de déchiffrement est toujours la même car elle ne fait pas apparaitre r11. La clef de chiffrement de __Shikata Ga Nai__ était différente à cha&que tour de boucle. C'était un point fort de __Shikata Ga Nai__, dommage de ne pas le réutiliser.

Une fois la boucle de chiffrement terminéee, on obtient bien notre payload décodée comme on peut le voir sur la figure suivante:

![image alt text](/images/encoder-zutto-dekiru/zutto_decoded.png)

L'étude de __Zutto Dekiru__ s'achève ici. On a pu constater une ressemblance frappante avec __Shikata Ga Nai__ bien que certains mécanismes d'obfuscation aient été enlevés, ce qui est bien dommage. En effet, dans __Shikata Ga Nai__, une partie du décodeur est encodé, ce qui n'est plus le cas ici. Et le fait de pointer au milieu d'une instruction pour commencer le déchiffrement a également été enlevé. Même chose concernant la modification de la clef de chiffrement à chaque tour de boucle.

De plus, alors que __Shikata Ga Nai__ change de clef de chiffrement à chaque tour de boucle, __Zutto Dekiru__ conserve la même clef ...

On peut dire que globalement les 2 encodeurs se valent, même si __Zutto Dekiru__ est légèrement moins puissant. Cependant, l'un fonctionne en x86 (Shikata Ga Nai), tandis que l'autre fonctionne en x64 (Zutto Dekiru).

