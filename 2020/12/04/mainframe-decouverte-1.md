
Si vous vous retrouvez ici, c'est que vous voulez en savoir davantage sur les __mainframes__. Je ne suis clairement pas un expert dans ce domaine, mais je vais tenter de donner des détails pertinents d'un point de vue de pentester et d'y apporter une vision moderne.

Pour découvrir quelque chose sur internet, rien de tel qu'un scan de port. L'outil de choix? __nmap__. Les ports ouverts du mainframe auquel j'accède sont: __22, 623, 4035, 5040, 5041, 5042, 10007, 10443__.

Ceux qui sont spécifiques et facilement identifiables à un mainframe sont dans le cas présent: __623, 4035 et 5042__. En effet, on peut voir sur les captures ci-dessous la correspondance de ces ports avec les services associés:

![image alt text](/images/mainframe/mainframe_port_623_4035.png)

![image alt text](/images/mainframe/mainframe_port_5042.png)

On y voit que le port __623__ est associé au service __TN3270__. Ce service correspond à la vision classique que l'on a du mainframe, à savoir __"l'écran noir"__ comme certain l'appelle. En se connectant sur ce port, et en utilisant Telnet, il est possible d'executer des commandes __TSO__ (j'y reviendrais par la suite). Les captures d'écrans ci-dessous présentent un aperçu de l'allure que cela peut avoir. Le premier screenshot a été "volé" à Google, car je n'avais pas d'émulateur 3270, et la seconde présente ce que j'obtiens avec une connexion Telnet classique

![image alt text](/images/mainframe/mainframe_tn3270.png)

![image alt text](/images/mainframe/mainframe_tn3270_2.png)

Voilà, ça c'est ce qui fait peur ! En vérité ca ressemble à ce que tout pentester aime avoir :D !

Le second port intéressant est le __4035__ qui correspond à __l'explorateur z0S FMID HALG300__. Le service est __RSE__ pour __Remote System Explorer__: nom qui attire toujours l'oeil d'un pentester, n'est ce pas? La documentation IBM est disponible: https://www.ibm.com/support/pages/sites/default/files/inline-files/$FILE/zexp_genericrse.pdf

Cependant, cela est moins séduisant que ça en l'air. En effet, RSE est un plugin Eclipse qui permet d'accéder au système de fichier distant. Je n'ai aucune intention d'installer Eclipse ... donc tant pis ...

Le troisième port pertinent que l'on a remarqué est le __5042__ qui correspond à une base de données: __DB2__. C'est __LA__ base de données d'IBM. C'est une base de donnée relationnelle utilisée majoritairement avec des charges de travail transactionnelles (banque, assurance, aviation, ...), typiquement utilisée sur un mainframe.

Il y a un autre port que je n'avais pas mentionné, c'est le __10443__. Un screenshot est présenté ci-dessous: 

![image alt text](/images/mainframe/mainframe_port_10443.png)

Cela ressemble fortement à un service web ... oui c'est le __ssl-cert__ qui me fait dire ça. Cependant lorsque l'on tente d'y acceder, on se prend un bon gros code retour __404__:

![image alt text](/images/mainframe/mainframe_port_10443_error.png)

On accedera au service derrière ce port par __VS Code__ et plus précisément par le plugins __ZOWE__. 

Eh oui, on peut accèder au mainframe via __VS Code__, si c'est pas moderne ça !

![image alt text](/images/mainframe/mainframe_vscode.png)

A partir de là, on peut soumettre des jobs à exécution, créer des fichiers, en supprimer, etc. C'est bien plus attrayant que le __TN3270__ :)

Il y a un autre port dont je n'ai pas fait référence, il s'agit du port __22__: le __ssh__. En effet, il y a maintenant une sorte de sous systeme linux sur mainframe. Il s'agit du __USS__ pour __Unix System Services__ et on peut y accèder via __VS Code__ bien sûr, mais aussi par le classique client ssh comme on peut le voir ci-dessous:

![image alt text](/images/mainframe/mainframe_ssh.png)

A partir de là, un pentester devrait s'y retrouver ^^. Il existe des différences par rapport à un linux classique notamment la possibilité d'exécuter directement des jobs sur la mainframe! Il existe des commandes supplémentaire par rapport à un linux de base. Pour soumettre un job depuis __USS__, il suffit d'utiliser la commande __submit__ et d'y entrer un __JCL__ à exécuter: 

![image alt text](/images/mainframe/mainframe_hw_jcl.png)

Le __JCL__ présenté ci-dessous effectue un simple __HELLO WORLD__:

```
//JCLPRGR  JOB
//STEP1 EXEC PGM=IEBGENER
//SYSUT1   DD *
HELLO WORLD
//SYSUT2   DD SYSOUT=A
//SYSPRINT DD SYSOUT=A
//SYSIN    DD DUMMY
//
```

On voit bien en bas du screenshot que le job soumis est le __JOB JOB01312__. Il doit exister une commande pour afficher le résultat d'un job en particulier, mais je ne l'ai pas trouvé :( On peut cependant voir le résultat de l'exécution du job dasn __VS Code__:

![image alt text](/images/mainframe/mainframe_hw_result.png)

On voit donc que l'on peut exécuter du code sur le mainframe assez facilement si l'on a des accès dessus.

Pour ceux qui se demandent ce qu'est le __JCL__, je préfère dire qu'encore une fois, je ne suis pas expert __JCL__ .. donc ..

__JCL__ est l'acronyme de __Job Control Language__ et est utilisé sur le mainframe pour exécuter des tâches. C'est un langage ancestral, j'en veux pour preuve cet output lors de l'exécution de mon hello world:

![image alt text](/images/mainframe/mainframe_jcl_card.png)

Vous voyez cet encadré rouge dans lequel il y a écrit __CARDS__ ... ça date de l'époque des cartes perforées !!! 

Il faut que le __JCL__ commence par la __carte JOB__ (voir le JCL hello world un peu plus haut). Chaque ligne correspond à une carte et donc à une tâche à effectuer. On le comprend, le JCL est similaire à l'exécution successive de carte et donc il apparait évident que l'ordre des cartes est important. Ce qui veut dire que l'on ne met pas ce que l'on veut où l'on veut !

Je remets le hello world vu précedemment ci-dessous et je vais détailler chaques cartes:
```
//JCLPRGR  JOB
//STEP1 EXEC PGM=IEBGENER
//SYSUT1   DD *
HELLO WORLD
//SYSUT2   DD SYSOUT=A
//SYSPRINT DD SYSOUT=A
//SYSIN    DD DUMMY
//
```

Tout d'abord, il faut savoir qu'une carte commence toujours par  __//__ et comme vous vous en êtes rendu compte: __il ne s'agit pas de commentaire !__

La déclaration __EXEC__ permet d'identifier le programme qui executera l'étape __STEP1__. Ici il s'agit du programme __IEBGENER__. __IEBGENER__ permet de générer un __data set__. Pour fonctionner __IEBGENER__ a besoin de 4 __Data Definition__ (__DD__) que l'on retrouve dans les cartes suivantes:

* __SYSIN__ permet de lire les parametres de controle. Lors d'une utilisation simple de __IEBGENER__, on peut simplement specifier la __Data Definition__ comme étant __DUMMY__.
* __SYSPRINT__ est utilisé afin d'afficher les messages en provenance de __IEBGENER__.
* __SYSUT2__ est utilisé comme sortie de __IEBGENER__. C'est donc là que l'on regardera si __HELLO WORLD__ a bien été écrit.
* __SYSUT1__ est l'entrée de __IEBGENER__, et c'est donc là que l'on spécifie le message d'entrée.

Il faut savoir que le __JCL__ ne peut avoir que 255 étapes. Ainsi si l'on veut pouvoir faire des programmes complexes, il faut un autre moyen.

Le plus souvent le __JCL__ est utilisé pour exécuter du __COBOL__. __COBOL__ est un acronyme pour __COmmon Business Oriented Language__. C'est un langage fait pour le business ! Il a été conçu de sorte à ce qu'il soit lisible par n'importe qui, car lors d'un audit on veut que n'importe quel auditeur puisse controler le code. Ainsi il n'est pas nécessaire d'être un développeur expert pour comprendre le sens d'un code __COBOL__.

Le __COBOL__ est essentiellement utilisé sur les mainframes et c'est donc un langage de choix pour les banques, assurances, etc. Quand on touche à l'argent, on ne veut pas d'obscurantisme ni d'obfuscation. On veut de la clarté !

Il existe différent type de __COBOL__. Celui que l'on retrouve sur les mainframes est __l'ENTERPRISE COBOL__. Le __COBOL__ est un langage __column-dependant__ (c'est peut être pas le bon terme ...), ce qui signifie que les colonnes sont importantes (un peu comme en python mais en pire !!). Les commentaires sont sur une colonne bien spécifique, le code sur d'autres colonnes bien spécifiques, le nom des sections également, etc.

Un hello world en __COBOL__ ressemble à ça:

```COBOL
       IDENTIFICATION DIVISION.
       PROGRAM-ID.    HELLOCBL.
       AUTHOR.        Z06603.

       ENVIRONMENT DIVISION.

       DATA DIVISION.

       PROCEDURE DIVISION.
      
       A000-START.
           DISPLAY "HELLO WORLD".
           STOP RUN.
```

On y voit __4 divisions__:

* IDENTIFICATION DIVISION
* ENVIRONMENT DIVISION
* DATA DIVISION
* PROCEDURE DIVISION

Chaque division peut avoir des sous-division que l'on appelle des __SECTIONS__. ET chaque __SECTIONS__ peut avoir des sous-sections que l'on appelle des __PARAGRAPHES__, et chaque __PARAGRAPHES__ peut contenir des __MOTS__. Chaque phrase se termine par un __.__ (point). C'est donc un langage qui se __lit__.

Le __JCL__ qui permet d'exécuter ce programme __COBOL__ doit d'avoir le compiler, puis l'exécuter:

```
//HELLOJCL  JOB
//***************************************************/
//COBRUN  EXEC IGYWCL
//COBOL.SYSIN  DD DSN=&SYSUID..SOURCE(HELLOCBL),DISP=SHR
//LKED.SYSLMOD DD DSN=&SYSUID..LOAD(HELLOCBL),DISP=SHR
//RUN       EXEC PGM=HELLOCBL
//STEPLIB   DD DSN=&SYSUID..LOAD,DISP=SHR
//SYSOUT    DD SYSOUT=*,OUTLIM=15000
```

La carte __COBRUN EXEC IGYWCL__ permet de désigner le compilateur __COBOL__. La carte __COBOL.SYSIN__ l'endroit où trouver le programme __COBOL__. La carte __LKED.SYSLMOD__, l'endroit où mettre le programme compilé. Les autres cartes sont assez explicites.

Il est ainsi possible d'exécuter de nombreuses ligne de code et l'on n'est pas limité par les 255 étapes maximales du __JCL__.

Bien que seul le __JCL__ permette d'exécuter des jobs. Il existe d'autres langages que l'on peut exécuter sur un mainframe. Un autre langage natif et ancestral est le __Rexx__. Il est possible d'exécuter du __Rexx__ directement depuis __TSO__ ou bien depuis __USS__. C'est donc un langage extremement puissant et qu'il faut connaitre si l'on veut jouer avec un mainframe.

Bien qu'apprendre le __Rexx__ soit intéressant, on peut noter que __python3__ est aussi présent ainsi que __Bash__ sur __USS__, ce qui laisse entrevoir des perspectives. Il existe même une librairie python  maintenue par IBM pour interagir avec z/OS (https://www.ibm.com/support/knowledgecenter/SSKFYE_1.0.1/python_doc_zoautil/index.html?view=embed)

On a rapidement parlé un peu plus haut du port 623 qui hébergeait le service __TN3270__. A travers ce service, on peut exécuter des commandes __TSO__. __TSO__ est l'acronyme de __Time Sharing Option__. C'est un interpreteur de commande intéragissant avec le mainframe (z/OS). Il est indispensable de connaitre __TSO__ pour piloter un mainframe !

Il existe 2 langages disponibles sous __TSO__: 

* __CLIST__
* __Rexx__

On peut aussi exécuter directement des commandes __TSO__, comme par example:

* LISTCAT
* LISTUSER
* ALLOCATE
* etc

La liste complete est donnée par la commande : __HELP__, et une grande partie des commandes sont disponibles dans la documentation (https://www.ibm.com/support/knowledgecenter/en/SSLTBW_2.2.0/com.ibm.zos.v2r2.ikjc200/ikj2o20037.htm)

J'espère que ca vous aura donner envie de vous pencher un peu plus sur les mainframes !

Dans un prochain article on verra comment coder un __reverse shell TSO en Rexx__ et comment il permet d'executer des commandes __TSO__ depuis un __nc__ ou un __listener metasploit__ sur un mainframe! On rentrera donc un peu plus dans certains détails ! 
