
"Patcher" est une technique qui consiste à modifier le contenu d'une image d'un exécutable afin d'en modifier ses fonctionnalités. Cela peut-être utilisé pour enlever un mécanisme d'authentification, un nag screen, ou bien pour rajouter des fonctionalités comme un reverse shell, un ransomware, ... 

Les possibilités sont infinies et les compétences requises peuvent être acquises rapidement. 

Dans cet article, je vais présenter une manière de patcher un PE afin d'y inclure du code.

Le PE que je vais utiliser est un classique, il s'agit de __putty__ en version __x64__. En effet cet outil est très utilisé et est donc un outil de choix à **backdoorer** pour un attaquant.

Lorsque l'image de l'exécutable est chargée en mémoire, la "première" instruction à être exécutée se situe à l'__entry point__, comme on peut le voir sur la capture ci-dessous.

![image alt text](/images/blog/backdoor-PE/oep.png)

On y voit plusieurs choses importantes à retenir:

* l'adresse de l'entry point: __0x00007FF736E69384__
* l'instruction située à l'entry point: __sub rsp, 0x28__
* les valeurs contenues dans les registres: __rax, rbx, rcx, ...__

L'entry point (EP) est une adresse importante car nous allons patcher l'instruction s'y situant (__sub rsp, 0x28__) afin de rediriger le flot d'exécution du programme vers une autre zone mémoire. 

Il est donc important de retenir l'adresse suivant l'entry point (__00007FF736E69388__) car une fois notre redirection effectuée, et notre code exécuté, nous aurons envie que le programme puisse continuer son exécution et démarrer correctement. On utilisera pour cela un __jmp 00007FF736E69388__.

Cependant, on ne peut pas hardcoder cette valeur car il y a de forte chance que l'ASLR (Address Space Layout Randomization) soit en place. L'ASLR permet de modifier les adresses de chargement des DLLs, les adresses de la stack, de la pile, ... Et donc il est quasi sûr que cette adresse ne sera pas la même sur votre poste d'essai.

Les valeurs contenues dans les registres sont importantes car à ce stade, on ne sait pas ce que représente ces valeurs, elles peuvent alors être importantes pour l'exécution du programme. 
Comme on veut que celui-ci reste fonctionnel, il ne faut pas les modifier. En __x86__, il existe deux instructions très utiles pour sauvegarder/restaurer les registres et les flags:

* pushad/popad
* pushfd/popfd

Malheureusement ces instructions n'existent pas en __x64__. Il faudra donc les sauvegarder à la main.

Venons en au fait. Où rediriger le flot d'exécution? S'il existe des caves de code , il est idéal de les utiliser. Les cave de codes sont des portions de code non utilisé par le programme. Les compilateurs actuels sont optimisés pour réduire les caves de code, il ne faut donc pas trop y compter. Dans ce cas, il faut ajouter une section afin d'y placer notre code.

Une PE contient plusieurs sections, comme par exemple .text, .data, .rdata, ... Chaque section à des permissions qui lui sont propres. Par exemple, la section .text qui contient le code exécutable a les permissions __RE__ (Readable, Executable), la section .data qui contient les strings, les constantes a les permissions __RW__ (Readable, Writeable). En effet, il n'est pas nécesaire que la section .text soit __Writeable__ car personne ne veut avoir du code automodifiable, ... quoique (pour info, pour avoir du code automodifiable, utile pour un packer par example, il faut modifier les  permissions en utilisant par example la fonction __VirtualProtect()__) . Il n'est pas non plus nécessaire de pouvoir exécuter du code dans la section .data, c'est pourquoi elle n'est pas __Executable__.

Les sections ainsi que les permissions associées de putty sont présentées sur la capture ci-dessous.

![image alt text](/images/blog/backdoor-PE/sections.png)

Il faut donc ajouter une section __RE__ à notre image afin de pouvoir lire et exécuter du code. Pour ajouter une section et ajuster les permissions, j'utilise l'outil __LordPE__. J'ajoute une section que j'appelle __.PWNEY__ et je lui attribue une taille de __1000 octets__ avec les permissions __RWE__ (writeable juste au cas où j'ai envie de faire du code automodifiable à l'intérieur en utilisant un encodeur par exemple).

On peut voir ces modifications sur la capture ci-dessous.

![image alt text](/images/blog/backdoor-PE/newsections.png)

A cette étape, on a juste ajouté une section, mais aucune modification au PE n'a été effectuée. On peut le constater rapidement en regardant la taille de celui-ci. On y a ajouté une section de 1000 octets, il devrait donc être plus gros de 1000 octets. Or il n'en est rien, on a en réalité juste spécifier que la section __.PWNEY__ doit faire 1000 octets. Il faut pour cela lui ajouter du code afin de remplir la nouvelle section. Pour cela j'utilise __HxD__. Afin de savoir où ajouter du code, je regarde sur la figure précédente, la ligne __RawOffset__ qui me donne un offset et qui est donc indépendant de l'ASLR. C'est à cet emplacement que je vais ajouter du code (1000 octets) pour remplir la section, comme on peut le voir ci-dessous.

![image alt text](/images/blog/backdoor-PE/fillbytes.png)

On peut maintenant modifer l'EP afin d'effectuer un jmp vers cette section. Cependant, un petit problème surviendra au moment d'un reboot de la machine ou bien lors de l'exécution de l'image sur un autre ordinateur. En effet, l'ASLR est activé par défaut, ce qui rend aléatoire les adresses mémoires. Dans un premier temps, désactivons l'ASLR pour ce binaire en particulier. J'utilise pour cela __CFF explorer__ comme présenté sur la figure suivante (il faut décocher la case __DLL can move__):


![image alt text](/images/blog/backdoor-PE/aslr.png)

L'entry point sera alors différent de ci-dessus, mais sera toujours le même lors d'un reboot de la machine.

![image alt text](/images/blog/backdoor-PE/newoep.png)

L'adresse mémoire de la section __.PWNEY__ est alors __0x1400D6000__. On remarque au passage que la partie basse de l'adresse est la même: 6000. En effet, la randomization des adresses ne s'effectue que sur la partie haute, tandis que la partie basse retranscrit en quelque sorte les offsets.

Il faut alors patcher l'entry point avec un __jmp 0x1400D6000__ afin de jumper sur la section __.PWNEY__.

![image alt text](/images/blog/backdoor-PE/patchoep.png)

Le fait d'avoir remplacer le __sub esp, 0x28__ par un __jmp 0x14006000__ a modifié les instructions suivantes. En effet le nombre de bytes utilisés pour coder l'instruction __sub esp, 0x28__ n'est pas le même que celui utilisé pour coder l'instruction __jmp 0x140D6000__. 

Suite à l'exécution de notre patch dans la section __.PWNEY__ il faudra effectuer un jump à l'adresse __0x1400A938D__ tout en ayant pris soin d'effectuer le call qui a été tronqué lors de notre patch de l'entry point.

On peut commencer à travailler dans la zone mémoire liée à la section __.PWNEY__. Il faut d'abord sauvegarder l'état des registres et des flags afin de les restaurer ensuite. Comme il n'existe pas d'instruction pour pusher sur la stacks l'ensemble des registres étendues (rax, rbx, ...) comme il y a pour du x86 (__pushad__ push sur la stack eax, ebx, ...), il va falloir le faire à la main. Il faut aussi sauvegarder les flags avec l'instruction __pushfq__ (__pushfd__ en x86)

![image alt text](/images/blog/backdoor-PE/pushreg.png)

A la fin de la zone mémoire liée à la section __.PWNEY__, il faudra faire l'étape inverse.

![image alt text](/images/blog/backdoor-PE/popreg.png)

Il faut ensuite ajouter les instructions que l'on a patché à l'entry point ainsi que le jump vers l'instruction qui suit l'entry point pour reprendre le flot normal d'exécution du PE.

![image alt text](/images/blog/backdoor-PE/end.png)

Avant d'insérer du code malveillant entre la "zone de push" et la "zone de pop", il faut maintenant enregistrer les modifications et vérifier que le programme fonctionne toujours. Si ce n'est pas le cas, il y a probablement un problème avec les registres où l'alignement de la stack. Il faut donc vérifier cela en premier.

Il faut retenir que l'on n'a pas sauvegardé l'état des registres FPU. Si on le souhaite, on peut regarder du côté des instruction __fstenv__, __fnstenv__, ... (utilisé par les encodeurs __Shikata Ga Nai__ au passage) pour cela.

On peut aussi retenir que l'ASLR ne posera aucun problème ici car les __jump__ et les __call__ sont tous relatifs au PE. Ainsi même si les adresses changent, les appels se feront toujours car ils sont relatifs au code exécuté.

L'ASLR posera problème si l'on ajoute du code qui dépend de l'emplacement des DLLs chargées. Par example, si je veux faire un __call VirtualAlloc__, il faudra d'abord que je connaisse l'adresse mémoire où est chargée la librairie __kernel32.dll__, puis l'adresse mémoire de la fonction __VirtualAlloc__.

Ou bien il faut utiliser du code indépendant de la position. Ca s'appelle ... un shellcode. Ok c'était facile.

N'importe quelle payloads issues de metasploit fera l'affaire car elles utilisent le __PEB__ pour trouver les adresses mémoires des modules chargés en mémoire.

A noter que si l'on utilise une payload de metasploit, il y aura un "petit soucis" dans le sens où celles-ci se terminent généralement par la fonction __WaitForSingleObject__ qui attend indéfiniment car le paramètre est passé à -1. Cela se traduit par le fait que putty ne se lance pas tant que la payload n'est pas exécutée. Ca peut être dérangeant dans le cas d'un reverse shell car le flot d'exécution ne continuera pas tant que l'attaquant n'aura pas fermé son shell distant.

Ainsi il faut patcher la payload metasploit afin soit d'enlever cette fonction, soit de réduire la valeur d'attente de la fonction __WaitForSingleObject__.

Le PE est patché, fonctionnel et malveillant. Encore faut-il que la victime l'utilise... Comment le distribuer? On peut imaginer que l'attaquant ayant accès à une machine victime veuille remplacer un exécutable présent sur la machine afin d'avoir de la persistence. Imaginons qu'il s'agisse d'une machine de l'équipe de développement qui utilise quotidiennement putty pour se connecter en SSH sur des machines virtuelles de développement ...

On peut aussi imaginer qu'un attaquant à accès au share qui contient tout les exécutables que l'entreprise victime à le droit d'installer sur les postes des collaborateurs par le biais de GPO. Et ainsi patcher un de ces exécutables en y incluant un ransomware ...

Les applications sont infinies ... mais cela ne sert à rien si la payload est détectée par les antivirus présents sur les machines victimes. Les payloads metasploit sont connues des AV, c'est pourquoi je ne présente pas la manière dont inclure une payload metasploit dans un PE dans cet article. Le mieux est d'y ajouter une payload que vous avez developpé de sorte à bypasser les AV.


