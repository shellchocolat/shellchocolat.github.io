
Je présente ici un cracking de software ainsi que le moyen d'y injecter une backdoor sans modifier la taille du binaire. Je me permet de rappeler que le cracking de software est interdit, et qu'il ne peut être toléré qu'en ayant acheté une licence et dans un cadre purement éducationnel. Pour ces raisons, je ne divulgerais pas le nom de l'outil.

L'outil qui sera cracké ici est un desassembleur + debugger (dernière version de celui-ci à l'heure de l'écriture de l'article: __4.5.22__) fonctionnant sous Mac/Linux. Il ressemble à __IDA Pro__. La capture d'écran ci-dessous en présente une vue synthétique.

![image alt text](/images/crack-licence/example.png)

Ceux qui connaissent IDA Pro, on pu constater la ressemblance. L'outil est disponible en version d'essai avec quasiment toutes les fonctionnalités pendant un temps limité. Il est possible de voir ces limitations sur la figure ci-dessous:

![image alt text](/images/crack-licence/limitation.png)

Le programme est livré sous forme de paquet __.deb__ sous la version Linux. Pour l'installer:

```
dpkg -i mon_programme_4.5.22.deb
```

Le programme est alors disponible dans:

```
/opt/mon_programme/bin/
```

Lorsque l'on exécute le programme, on obtient le __nag screen__ suivant:

![image alt text](/images/crack-licence/registration.png)

Comme nous n'avons pas de licence, nous cliquons alors sur la version de démo. Le programme fonctionne correctement mais uniquement pendant 30 minutes. Ce qui nous empêche de travailler correctement, d'autant plus que l'on ne peut pas sauvegarder notre travail en cours. Il faut travailler vite, me dit-on ! :p

L'idée est de bypasser ces limitations, puis d'y insérer une backdoor et de **repackager** le binaire afin de le distribuer ... (__NON bien évidemment !__)

Regardons le programme dans __IDA Pro__. En regardant les __strings__ présentes dans le binaire, je me laisse attirer par tout ce qui concerne le mot __license__ (en anglais ^^). La figure suivante montre ce qui m'a paru pertinent:

![image alt text](/images/crack-licence/license_str.png)

__The computer license has been installed__  et __The licence file for %1 has been installed__ me paraissent claires comme de l'eau de roche. Ce sera un bon point de départ pour l'analyse du binaire. Lorsque l'on regarde les références de ces strings, on tombe sur ce qui est présenté ci-dessous:

![image alt text](/images/crack-licence/switch_case.png)

On s'aperçoit alors qu'il y a un __switch__ qui comporte 4 cas (les 4 flèches bleues). Ce switch permet d'exécuter différentes portions du code en fonction de la valeur située dans __rcx__ (__jmp rcx__).

On voit qu'il y a également un embranchement plus haut en fonction de la valeur situé dans __rax__ (cmp eax, 3). Si rax contient une valeur plus grande que 3, on ne passe pas dans la routine de validation. Il faut trouver la bonne valeur de __rax__ qui doit être comprise entre 0 et 3.

Comment est définie la valeur qui se trouvera dans __rax__?

De manière générale, le retour d'une fonction spécifie __toujours__ **quelque chose** dans __rax__. Ce peut être un booléen (True/False, 1/0), un handler, ... Dans ce cas présent, ce sera un entier compris entre 0 et 3, ce qui laisse donc 4 possibilités.

On a donc l'intuition que la fonction __sub\_5038B0__ permet de valider/invalider la licence en spécifiant suite à son exécution une valeur dans __rax__.

Cette valeur sera ensuite mise dans __ecx__ (__mov ecx, eax__). Une valeur (un offset) sera ensuite positionné dans __rax__ (__lea rax, off\_677FA0__). Regardons sur la figure suivant ce que vaut cet __offset__:

![image alt text](/images/crack-licence/switch_table.png)

On constate que cet offset donne des adresses de bases auxquelles on ajoutera le retour de la fonction __sub\_5038B0__ multiplié par 4 (__movsxd rcx, [rax+rcx*4]__). On y ajoutera ensuite le retour de la fonction __sub\`_5038B0__ (__add rcx, rax__), ce qui permettra de trouver la bonne adresse du __switch__. Bon je me rend compte que ce n'est pas facile d'écrire avec des mots le procédé. Le mieux reste de prendre le temps de regarder le bout de code pour bien le comprendre ^^

Toujours est-il que l'on a compris que la fonction __sub\_5038B0__ joue un rôle primordial dans le **licensing**. Regardons la **structure graphique** de cette fonction:

![image alt text](/images/crack-licence/license_graph.png)

Cette fonction semble complexe et contient 519 bytes quand même !!

En voyant le __switch__ précédent, on a pu voir que le cas __1__ (lorsque __eax = 1__) permet de dire que la licence est valide, ce qui est suffisant pour cracker le programme (pas besoin de reverse le mécanisme de validation). On peut alors décider de remplacer les 519 bytes de la fonction __sub\_5038B0__ par:

```
B8 01 00 00 00	mov eax, 1
C3		ret
```

C'est une manière de patcher qui fonctionne et qui permet d'enlever toute les limitations de la version de démo. On aurait pu décider également de ne pas toucher au corps de la fonction et de ne modifier que l'épilogue (la fin  de la fonction) en spécifiant que __eax = 1__. Dans le cas présent, il aurait fallu dire que __ebx = 1__ car:

![image alt text](/images/crack-licence/license_last_byte.png)

__Cependant__, on a pu voir que la fonction de validation de la license fait 519 bytes, ce qui est largement suffisant pour mettre un __reverse shell__ ou un __downloader__. Il suffit de remplacer l'ensemble de la fonction par notre charge malveillante, puis d'y ajouter à la fin les octets de validation de la licence (B8 01 00 00 00 C3). Nous aurons alors un logiciel cracké comportant du code malveillant sans que l'on ait eu besoin d'ajouter de section. On peut même s'arranger pour que la taille du code malveillant + des octets de validation fassent exactement 519 bytes (en ajoutant un padding de __nop__ par exemple), et ce afin de ne pas modifier la taille du binaire, et donc de ne pas paraitre suspect !

Bien évidemment je ne montre pas comment générer un __reverse shell__ ici, ni même comment l'inclure dans le code ... Ceux qui veulent, savent.

On a cracké le programme uniquement grâce à de l'analyse statique ! Ce fut facile ^^, 30 minutes aurait suffit, on aurait alors pu le faire avec la licence de démo de l'outil finalement he he. On peut tout de même avoir envie de vérifier que le patch fonctionne correctement en le débuggant. Mettons alors des __breakpoints__ sur toutes les fonctions qui font appel à cette routine de validation (__sub\_5038B0__). La figure suivant montre l'arborescence des fonctions qui font appel à __sub\_5038B0__:

![image alt text](/images/crack-licence/license_to.png)

On va donc mettre des __breakpoints__ sur les fonctions:

* sub\_63CBE0

* sub\_505920

* sub\_5036E0

* sub\_503B50

Puis exécuter le programme et modifier au fur et à mesure la fonction __sub\_5038B0__ par: 

```
B8 01 00 00 00	mov eax, 1
C3		ret
```

On constate que l'on valide bien la license et que l'on acquiert alors toutes les fonctionalités du programme !




