
Le cracking de software est une discipline à part entière (surtout interdite, achetez vos logiciels de test et faite cela que dans un esprit de recherche de connaissance à but non lucratif). Elle demande des compétences en assembleur, mais aussi en reverse engineering. Il faut également connaitre la structure du fichier que l'on souhaite cracker (PE, elf, ..), et également les différents mécansimes de protections de software qui existent sur le marché.

Suivant la qualité du software, il est fort possible que des mécanismes de protections soient mis en place, comme la détection de breakpoint logiciel, la mise en place de packer, le calcul et vérication d'un hash basé sur une version non patchée du software, ...

De manière générale, il est toujours possible de bypasser les mesures de protection. Il "suffit" de comprendre le fonctionnement du programme étape par étape. Le "il suffit" est un euphémisme bien entendu. Lire et comprendre le code desassemblé est une tache fastidieuse qui demande beaucoup de temps et de pratique. D'autant qu'un code desassemblé peut contenir des centaines de fonctions et des milliers de lignes de code. Il faut donc réussir à avoir de l'instinct quant aux fonctions qu'il sera utile ou non d'analyser.

Pour avoir cet instinct, il faut pratiquer. Je présente alors ici un cas d'école qui peut être vu comme un exercice de 1er niveau (hors crackme) pour appréhender le cracking. Le nom du software sera masqué, mais des indices évident sont présents (manque de rigueur quant à l'obfuscation) ...

La première étape consiste à savoir ce que l'on veut patcher: un nag screen, un mécanisme d'authentification, un déblocage de features payantes, une connexion réseau pour éviter un upgrade de version, ... 

Dans le cas présent, le software utilisé à toutes ses features activées mais pendant 40 jours seulement. Une fois ce délais dépassé, le software passe en mode restreint. L'objectif est alors d'activer la licence afin de conserver l'ensemble des features.

![image alt text](/images/crack-licence/2019-12-15-eval.png)

La seconde étape consiste à obtenir un point de départ. C'est le plus important car si l'on ne sait pas par où attaquer ces milliers de lignes de codes, on va se retrouver à analyzer l'ensemble du code, ce qui n'est pas envisageable.

Afin d'avoir un bon point de départ, il est possible de regarder l'__IAT__ (Import Address Table), mais aussi les strings  utilisées, ou encore d'exécuter le software puis d'y attacher un debuggeur et de regarder où se trouve les appels qui triggue le mécanisme voulu, ou bien de lancer le software dans un debugger puis de regarder la call stack, ...

Je précise ici que j'utiliserais __IDA pro__ pour l'analyse statique et __x64dbg__ pour l'analyse dynamique. __IDA pro__ est très pratique pour naviguer dans le code desassemblé et __x64dbg__ est un excellent debugger.

On voit sur la figure ci-dessus que la string "évaluation" apparait dans les deux fenêtres (au bas de la fenêtre *à Propos* et dans le titre de la *fenêtre principale*). Ce qui veut dire qu'à un moment donné dans le flot d'execution du code, une comparaison est effectuée afin de déterminer si la licence est activée ou non.

Si l'on regarde les strings contenues dans le software avec l'outil __bintext__ par exemple et que l'on effectue une recherche sur le mot "évaluation", on se rend compte que la recherche n'aboutit pas. La string "évaluation" n'est pas présente. On peut alors penser que la string doit être en anglais puis qu'elle est traduite ensuite au runtime. La string "evaluation" ou "evaluate" n'est pas non plus présente. Il est alors envisageable de penser qu'il y a un mécanisme de création de string au runtime, ou d'obfuscation. Pour ceux qui ont reconnu le software utilisé, il est quasi-évident qu'il n'existe pas ce genre de mécanisme de protection ...

Il existe un autre endroit où des strings peuvent être contenues. Il s'agit des ressources. En général c'est ici que l'on place les icones, les langues, la version, les menus, ... Pour regarder dans les ressources, on peut utiliser __IDA Pro__ ( on sort l'artillerie lourde; il faut cependant penser à l'activer car par défaut les resources ne sont pas chargées. Dans le cas présent, je vais utiliser __Resource Hacker__ et rechercher "evaluation". Le résultat est visible sur la figure suivante:

![image alt text](/images/crack-licence/2019-12-15-rh.png)

Dans les ressources, les strings sont contenues dans une tableau de strings. Ainsi, à chaque string correspond un indice auquel il faut faire reférence dans le code. On voit ici que la string "evaluation" a l'indice __873__. Il est à noter que le décimal n'est utile que pour les humains. Un ordinateur utilisera plutôt de l'hexadécimal, l'indice est alors __0x369__.

L'appel aux références se fait via:

```
mov ecx, 0x369
call somethingThatProcessStringIndex
```

On peut voir sur la figure suivante ce mécanisme d'appel à la resource 0x369 et 0x36A. Juste au dessus on y trouve un __ja short 13F19CE4F__. Cependant aucune de ces références n'est pertinente (*0x369 = evaluation copy*, *0x36A = Only %d days left to buy a licence*). Il n'y a donc pas d'intérêt à modifier ce mécanisme. 

![image alt text](/images/crack-licence/2019-12-15-bypass_eval.png)

On voit aussi qu'il y a un autre branchement un peu plus haut __jnz 13F19CEAF__ qui semble plus prometteur. Si l'on met un breakpoint logiciel dessus et que l'on modifie le Zero Flag (__ZF__) qui vaut __ZF = 1__ par __ZF = 0__, on modifiera l'action du __jnz__ (Jump if Not Zero) et l'on aura l'impression d'avoir bypasser le mécanisme de vérification de licence. __Il n'en est rien__. En effet, le mécanisme de vérification de licence est effectué bien avant, d'où le __cmp cs:13F236894, bl__. Cela signifie que la valeur stockée à l'adresse __13F236894__ est critique pour la validaion de la licence.

Cet espace mémoire est remplie au runtime. Afin de déterminer quelle fonction modifie cet espace mémoire, il faut y placer un breakpoint. Un breakpoint logiciel ne servira à rien sur un accès à un espace mémoire. Pour savoir quant un espace mémoire est lu ou écrit, il faut utiliser un breakpoint hardware comme on peut le voir sur la figure ci-dessous:

![image alt text](/images/crack-licence/2019-12-15-bp_hard.png)

Ainsi, à chaque fois que cet espace mémoire sera lu ou écrit, le flot d'exécution s'arretera et l'on pourra observer le mécanisme qui a effectué la modification.

En executant le programme à travers x64dbg, on remarque que l'espace mémoire __13F236894__ est écrit suite à l'instruction __call 13F19A700__ comme on peut le voir sur la figure ci-dessous. 

![image alt text](/images/crack-licence/2019-12-15-bp_hard_trig.png)

La valeur qui y est écrite lorsque l'on n'a pas la licence est __0__. On en conclut alors que c'est le retour de la fonction située à l'adresse __13F19A700__ qui permet de valider si la licence est activée ou non. Le code qui spécifie la valeur de __rax__ est présentée ci-dessous:

![image alt text](/images/crack-licence/2019-12-15-set_eax.png)

On y voit que sur la branche de gauche, __al__ est mis à __1__ puis la fonction se termine pour revenir à l'appelant et donc écrire __1__ à l'adresse __13F236894__ ce qui est différent de __0__ comme on a pu l'avoir précédemment. On imagine donc que la licence est alors validée quand, à ce niveau, __rax = 1__, et non validée quand __rax = 0__. Regardons alors un peu plus l'embranchement qui permet de passer la valeur de __rax__ à __1__:

![image alt text](/images/crack-licence/2019-12-15-set_eax_1.png)

On y voit un __test al, al__ puis un __jz__ (Jump if Zero). Il suffit alors de patcher le __jz__ en __jnz__ afin de bypasser le mécanisme de vérification de licence. En effet, cela mettra la bonne valeur à l'adresse __13F236894__ (c'est-à-dire __1__). Un __jz__ se note __0x74 0x04__ et un __jnz__ se note __0x75 0x04__. On peut aussi simplement y mettre des __nop__ (__0x90 0x90__).

![image alt text](/images/crack-licence/2019-12-15-patched.png)

Le lecteur interessé aura remarqué qu'il était possible de comprendre le mécanisme de vérification de licence en analysant la fonction située à l'adresse __13F11B188__. Mais il faut s'accrocher pour la crypto ... surtout en assembleur ...

On remarque aussi que la licence n'est attribuée à personne, il peut être intéressant de patcher cela également.

Cela met fin à cet article. En guise de conclusion, on peut dire que cela peut être vraiment très facile de patcher un software de sorte à bypasser certains mécanismes de licence ou d'authentification. Il faut cependant modérer ces propos car en effet, c'est un software extrêmement simple avec très peu de protection (aucune?). Je pense d'ailleurs que les developpeurs sont bien au courant de ces problèmes, et ne cherchent pas à les corriger. Rappelons également que ce genre de pratique est interdite et ne peut être faite dans un objectif de fraude. Meme en bypassant le mécanisme de licence, je vous encourage à payer le logiciel. Des developpeurs ont bossé dessus, il est normal d'être rémunéré pour ce travail.


