# Forensic sur une eMMC d'un téléphone wiko

J'avais un vieux téléphone qui contenait des photos que je voulais sauvegarder sur un disque dur, mais lorsque je mis la main dessus, je me suis rendu compte que la batterie avait gonflé et avait quasiment explosé le téléphone. Je n'avais pas de moyen de me brancher dessus, ni même de l'allumer.

Hum hum ...

Il ne me restait plus qu'à l'ouvrir, et dumper directement les données qu'il contenait, en espérant que le contenu ne soit pas chiffré.

Une fois démonté, le téléphone ressemble à ceci:

![image alt text](/images/forensic-emmc-wiko/shield.png)

![image alt text](/images/forensic-emmc-wiko/shield-off.png)

On voit qu'il y a un __shield__ qui sert de cage de Faraday afin de protéger les éléments qui sont dessous des sources électromagnétiques et radio fréquence. Et en dessous on y voit 3 composants:

* Samsung KMK7X000VM-B314: eMMC 8 Go

* Mediatek MT6580A: processeur ARM Cortex-A7, 32 bits, 1,3 GHz

* Mediatek MT635DV: je ne trouve pas la doc

C'est l'eMMC qui contient les différentes partitions, dont les partitions utilisateurs qui contiendront mes photos. C'est donc ce composant que je vais désouder afin d'en extraire le contenu.

Une __eMMC__ est une __MMC embedded__, et donc basiquement une __MultiMediaCard__. Une MMC se branche sur un ordinateur et se monte comme un disque classique. Cependant, ici on n'a pas une MMC classique. Le composant est un __BGA__ (__Ball Grid Array__), c'est-à-dire que les soudures sont sous forme de billes et sont situées sous le composant, elles ne sont donc pas apparentes. Il y a toute une technique de soudure/désoudure pour travailler avec ses composants.

Pour être franc, je n'aurais clairement pas pu réaliser cette tache sans les conseils avisés et précieux d'un de mes collègue avec qui j'ai davantage appris en 1 journée que tout seul en une dizaine d'années. Donc, merci Ludo !

Généralement ces composants supportent différents mode de communication, sur 8 bits, sur 4 bits et même sur 1 bit. En mode 1 bit, la communication avec le composant est très lente, mais comme il sera fastidieux de souder les fils sur les billes, ce sera probablement le plus simple. De plus l'outil qui me servira d'interface entre l'eMMC et mon pc ne supporte que le mode 1 bit (https://shop.exploitee.rs/shop/p/microsdemmc-breakout-board). Une photo de l'outil en question est présentée ci-dessous:

![image alt text](/images/forensic-emmc-wiko/exploitee.png)

Cet outil d'__exploitee__ coute 3 euros, et permet de convertir un cablage eMMC vers un cablage microSD !! On y voit les pins suivant:

* DATA_0 : mode 1 bit (en mode 8 bits, on a DATA_0 à DATA_7)

* CLK

* CMD

* VCCQ

* VCC

* GND

On aura donc besoin de souder 6 fils sur l'eMMC. Mais avant ça, il faut la désouder. La question de comment désouder un composant BGA est tout à fait légitime? Un des points important est de préchauffer le dessous du pcb (qui supporte le composant) de manière à éviter les trop forte dilatations thermiques qui pouraient conduire à une rupture du PCB ou même du composant. J'utilise pour cela un pistolet à air chaud d'art créatif ... oui je n'ai pas les moyens d'acheter un pistolet à air chaud à température et flux réglable.

Une fois préchauffé, je mets du flux (https://www.amazon.fr/MG-Chemicals-P%C3%A2te-nettoyage-Seringue/dp/B00425FUW2) sur les bords du composant, puis je passe le pistolet à air chaud de manière uniforme sur le composant tout en le tirant légérement avec un __twiser__ (une pince). Le flux va alors passer sous le composant puis se faufiller entre les billes ce qui aidera à la répartition uniforme de la chaleur tout en évitant l'oxidation.

![image alt text](/images/forensic-emmc-wiko/bga-not-removed.png)

![image alt text](/images/forensic-emmc-wiko/bga-removed.png)

Une fois désoudé et nettoyé on peut voir les emplacement des billes sous le composant. Il existe différents type de eMMC, et donc le pinout peut varier en fonction de celles-ci. On peut regarder sur ce site https://www.emmc-pro.com/blog.php?id=1 pour trouver le pinout de l'eMMC que l'on étudie. En ce qui concerne la mienne, elle est packagée dans un __BGA 162__, le pinout est donc comme suit:

![image alt text](/images/forensic-emmc-wiko/bga162-pinout.png)

Il faut ensuite souder les fils, sur les emplacements des billes. Là c'est une affaire de patience. Il faut s'assurer d'avoir des fils suffisament fins, du __0.1 mm__ et même longueur. Il est préférable de souder les fils verticalement ou en biais de manière à ce qu'il ne fasse pas court-circuit avec un emplacement étamé à côté de lui.

On peut voir ci-dessous le résultat de cette manip'

![image alt text](/images/forensic-emmc-wiko/result.png)

Ne pas hésiter à utiliser un microscope ou une loupe pour être sûr de souder au bon emplacement. Le flux est aussi de rigueur !

Il ne reste plus qu'à brancher l'outil d'__exploitee__ (eMMC vers microSD) sur un lecteur de microSD qui supporte le mode 1 bit ! De base le mien ne fonctionnait pas. Je n'ai pas trouvé de lecteur dont les spécifications indiquent les différents modes de fonctionnement, c'est une histoire de chance dans mon cas. Il ne faut pas miser sur la performance du lecteur à lire/écrire vite, bien au contraire, il faut qu'il aille le plus lentement possible, car si le lecteur ne fonctionne pas en mode 1 bit, on ne pourra pas lire les données dans notre cas. Un lecteur de vieille génération a fonctionner dans mon cas.

La figure ci-dessous montre l'ensemble branché sur le pc.

![image alt text](/images/forensic-emmc-wiko/plugged.png)

On peut maintenant voir que les partitions sont disponibles (il y en a quand meme 21 !!), il ne reste plus qu'à les monter. Sauf que non ! N'oublions pas que l'on fonctionne en mode 1 bit, donc très lentement. Il vaut mieux faire une copie bit à bit, puis travailler sur cette copie:

![image alt text](/images/forensic-emmc-wiko/mount.png)

```
$ dd if=/dev/sdc of=wiko-emmc.img status=progress
```

On vérifie très vite que les données ne sont pas chiffrées, et je peux alors récupérer mes photos !!! On peut évidemment récuperer l'ensemble des données comme les textos, les numéros, les applications, etc.

Ce fut un travail de longue haleine. Il a fallu être patient et méticuleux, mais aussi avoir les bons outils. A ce sujet, il existe des outils professionnels pour cela (https://www.amazon.fr/Medusa-complet-avec-eMMC-douilles/dp/B08NG784K4) mais il faut débourser environ 500 euros. Pour ma part j'aurais déboursé 3 euros pour le convertisseur eMMC vers microSD, et une dizaine d'euros pour le lecteur microSD.