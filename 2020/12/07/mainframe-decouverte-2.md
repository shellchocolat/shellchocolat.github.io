
Vous avez lu la partie 1 (https://dokyx.fr/mainframe_decouverte_1) et ça vous a plu ?

Ici je vais présenter les éléments qui permettent d'appréhender l'architecture d'un mainframe, ce qui donnera des pistes d'attaques en faisant le parallèle avec des systèmes mieux connus comme windows, linux, ..

Un mainframe est constitué d'une ou plusieurs unités qui sont appelés des __CEC__ pour __Central Electronic Complexes__. Bien sûr un mainframe peut être connecté à des appareils extenes comme des disques, des imprimantes, des équipements réseaux, des connexions LAN, des clefs usb, ...

Lorsque l'on parle de Mainframe, on pense souvent à __z/OS__ qui est le système d'exploitation principal des mainframes. Mais il en existe plusieurs comme par exemple:

* z/OS
* z/TPF
* z/VM
* z/VSE
* USS

Le __CEC__ est contrôlé par un pc et est connecté à celui-ci par une connexion filaire direct LAN. Cet ordinateur qui permet de se connecter au système est appelé un __HMC__ pour __Hardware Management Console__. Le __HMC__ permet de faire tout ce que l'on souhaite sur le mainframe. Il peut l'éteindre, le redémarrer, modifier la configuration des __CEC__, etc. C'est donc un équipement d'importance qui mérite une attention toute particulière.

Le __HMC__ est protégé par un login et un mot de passe, mais on peut aussi s'y connecter à l'aide d'un certificat SSL lié à un user id.

Il est aussi possible de se connecter au mainframe en utilisant __TSO__ ou __ISPF__ plutôt que le __HMC__.

On verra par la suite que de nombreuses informations concernant ces connexions sont stockées dans des fichiers de log pour investigations futures. Les fichiers sont stockés, non pas dans des dossiers, mais dans des __datasets__. On a une arborescence de type __DNS__. Imaginons que l'on souhaite à la base de donnée __RACF__ (que l'on verra par la suite), il faut y faire référence comme suit: __SYS1.RACFPRM1__ et pour la sauvegarde de __RACF__, __SYS1.RACFBCK1__. Les __datasets__ sont enregistrés sur disques bien entendu, mais il y a possibilité de les enregistrer sur bande magnétique !! Les datasets disposent d'autorisation, ainsi tout les utilisateurs ne peuvent pas tous acceder aux mêmes ressources, ce qui est la base ! Les accès disponibles sur un dataset sont:

* READ: lit un fichier ou parcourt un dataset
* UPDATE: update un dataset existant ou un fichier
* ALTER: modifie ou crée un dataset ou un fichier
* EXECUTE: exécute un programe dans un dataset

Comme on l'a vu plus haut, il existe différent système d'exploitation que l'on peut installer sur un mainframe. Il est à noter que __z/OS__ ne contient aucun mécanisme de sécurité. La sécurité de z/OS est donc effectué par un composant tiers, que l'on appelle un __ESM__ pour __External Security Management__, comme:

* RACF
* CA Technologies CA ACF2
* CA Technologies CA Top Secret

Le plus populaire des __ESM__ est __RACF__ et permet de:

* stocker et valider les users, passwords
* valider l'accès aux fichiers et datasets
* valider les accès aux autres ressources
* enregistrer les accès aux fichiers et datasets

Ce n'est donc pas __z/OS__ qui va gérer les accès et le logging des utilisateurs, mais __RACF__ (__Resource Access Control Facility__) ou __CA ACF2__ ou __CA Top Secret__. Ces composants ont été initialement developpés entre 1970-80 et ont été améliorés au fur des années.

Sur z/OS le nom d'utilisateur est composé de 8 charactères maximum (1 étant le minimum) et n'est pas sensible à la casse (majuscules obligatoires) ! De plus il doit commencer par un lettre et les charactères spéciaux ne peuvent être que @,$,# ce qui laisse l'opportunité de deviner les utilisateurs !

Les passwords font aussi 8 charactères !! Mais il est possible de définir une passe-phrase jusqu'à 100 charactères (rarement mis en place ..).

__L'ESM__ se comporte un peu comme une __GPO__ dans le sens où il est possible de définir la fréquence de changement d'un mot de passe, la longeur minimum et maximum d'un mot de passe, le droit d'utiliser un ancien mot de passe, si celui-ci peut/doit contenir des charactères spéciaux, suspendre un utilisateur, définir le nombre d'echec de login, etc.

Il va sans dire qu'il est possible de créer des groupes et d'appliquer les règles de sécurité à un groupe spéficique plutôt qu'à chaque utilisateur un par un. Il est intéressant de noter qu'il est possible de faire correspondre un logon id et un groupe sur z/OS à un uid et un gid sur USS (linux sur mainframe). Ainsi on peut se connecter à z/OS ou USS avec les mêmes identifiants grâce à l'__ESM__.

La base de donnée de l'__ESM__ contient les règles et les users id  et est donc critique, c'est pourquoi des sauvegardes sont réalisées régulièrement. Il est possible d'accèder à la console de management de l'__ESM__ par __TSO__ou __ISPF__ et les utilisateurs autorisés ont donc des commandes supplémentaires permettant d'effectuer les tâches d'administration de l'__ESM__. 

On va regarder à présent le mécanisme de logging des accès, login, etc. Ce point est important pour un pentester car il doit connaitre au mieux les évenements qui sont loggés en base. __z/OS__ a un mécanisme de log système qui lui est propre et qui s'appelle __SMF__ pour __System Monitoring Facility__ (on remarquera qu'IBM ne va pas chercher bien loin les noms de ces composants ^^).

Le __SMF__ permet de logger les logs opérationnelles (__operlog__) et les logs systèmes (__syslog__) auxquelles on peut accèder via __TSO/ISPF__ évidemment.

Les différents composants du mainframe, comme DB2, CICS, RACF, CA Top Secret, etc ont des logs qui peuvent être enregistré via __SMF__. Chaque composants à un code qui lui est attribué afin de pouvoir effectuer des recherches spécifiques dans les logs. Par exemple, CICS à la numéro 110 qui lui est attribué, DB2 les numéros 101 et 102, RACF le numéro 80, etc.

A chaque fois qu'un dataset ou un fichier est ouvert, crée, supprimé ou renommé, une entrée dans le fichier de log est crée ! Imaginez vous ce que cela représenterais sur votre linux préféré ! A chaque fois que vous faites un ls, une ligne de log. Un cd, une ligne de log. Un cat, une ligne de log, etc. Ces logs contiennent le logon id qui a effectué l'action, la date et l'heure ainsi que le nom du dataset/fichier. 

De même si l'action est effectué par une tâche, un programme, une transaction. Une ligne de log avec les informations concernant le job, CICS, DB2 qui a effectué l'action. On est à la limite de la paranoïa !! 

De plus, l'__ESM__ peut écrire des enregistrements __SMF__ et ainsi logger:

* access violation
* échec de connexion via mot de passe éronné
* modification des règles ou permissions
* création, suppression ou modification d'un user id
* etc

Imaginez le volume de données ! Ces logs très sensibles et sont conservées au minimium 7 ans. C'est tout simplement __insane__ !

Afin d'être exécuté, un service vérifie à l'aide de l'__ESM__ si les permissions de l'utilisateur sont correctes. Cependant certains services ne peuvent pas utiliser l'__ESM__. Parmi ceux-ci:

* z/OS lui-même
* ESM lui-même
* tâches qui sont lancées avant que l'ESM soit lancé
* taches qui nécessite de la performance et qui ne peuvent pas perdre de temps avec l'ESM

Dans ces cas là, il existe un autre mécanisme: l'__APF__ pour __Authorized Program Facility__. On peut le comparer à l'__UAC__ de windows. Lorsque l'__APF__ assigne une autorisation à un service/tâche/programme, cette autorisation ne peut pas être modifié durant le process d'exécution du service, et il n'est donc pas possible de lancer un service d'un état non autorisé en un état autorisé (protection contre les élévations de privilèges).

Une tâche autorisé est très puissante dans le sens où elle peut appeler n'importe quel service et donc faire ce qu'elle veut. Pour un attaquant, c'est une victoire ! Par exemple, une tâche autorisé par l'__APF__ peut accéder à n'importe quel dataset, modifier les permissions de n'importe quel utilisateur ou même éteindre le système.

Il existe plusieurs moyens pour qu'une tâche soit autorisé par l'__APF__. Un programme appelé par un programme autorisé par l'__APF__ devient alors autorisé par l'__APF__. Un programme appelé dans un JCL est autorisé par l'APF si il est appelé depuis une librairie autorisée par l'__APF__ __ET__ s'il est linké avec l'autorisation __AFP__ (AC=1).

Pour linké un programme avec l'autorisation __APF__, il existe plusieurs moyens:

* ld -b "AC=1" prog.o (linux)
* //LKED EXEC PGM=IEWL, PARM='AC=1' '(JCL)
* //SYSIN DD * SETCODE AC(1) (JCL)
* c89 -w l,'AC=1' prog.c (compilation)

Pour vérifier depuis la ligne de commande si un programme est autorisé par l'__APF__, il faut faire (USS) __ls -E__ comme le screenshot suivant

![image alt text](/images/mainframe/mainframe_apf.png)

On y voit le __a__ qui signifie que le programme est autorisé par l'__APF__. Pour donner cette autorisation à un programme, il y a la commande (USS) __extattr +A /z06603/SOURCE/prog__. Cette commande n'est normalement pas utilisable par n'importe quel utilisateur.