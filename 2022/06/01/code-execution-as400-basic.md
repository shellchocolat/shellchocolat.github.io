# Execution de code sur AS400

On va parler ici de création d'un __hello world__ sur __AS400__ en __Cobol__. En quoi c'est intéressant?

L'__AS400__ est une machine d'IBM qui peut-être vue comme appartenant à la famille des mainframes. L'OS qui tourne sur un __AS400__ et l'__OS400__. Comprendre le fonctionnement d'un __AS400__ permet donc d'apréhender les sytèmes underground qui font tourner le monde.

Pour se connecter sur un AS400, il faut utiliser __TELNET__ (port 23). Le plus simple est d'utiliser un émulateur __TN3270__. Pour ma part j'utilise un __TN5250j__.

Cet article sera essentiellement un aide-mémoire pour avoir une trace des commandes que j'ai utilisé. En parlant de ça, une commande sur AS400 s'appelle une __CL command__. Non, ce n'est pas l'abréviation de __Command Line__, mais celle de __Control Language__.

Avant de coder sur __AS400_, je vais décrire rapidement la strucutre de fichier. Je la vois un peu comme une bibliothèque. Il peut y avoir plusieurs étagère dans une bibliothèque. Dans chaque étagère, plusieurs livres. Et dans chaque livre, plusieurs chapitres.

Par analogie, l'étagère est une __library__, les livres sont des __files__ et les chapitres des __members__. Ainsi, il existe plusieurs __libraries__ qui sont toutes au même niveau. Il ne peut pas y avoir de __sub-library__, car il n'est pas possible de rentrer une étagère dans une étagère. Il peut en revanche y avoir plusieurs __files__ dans une __library__, et plusieurs __members__ dans un __file__.

Ceci étant dit, je commence par créer une __library__ qui me servira à contenir mes programmes (__CRTLIB - CReaTe LIBrary__):

```
CRTLIB LIB(MYLIB) TEXT('WILL CONTAIN MY PROGRAMS')
```

# Cobol

J'ai ensuite besoin de créer un __file__ qui contiendra mes codes sources __Cobol__ (__CRTSRCPF - CReaTe SouRCe Physical File__):

```
CRTSRCPF FILE(MYLIB/QCBLSRC) TEXT('MY COBOL PROGRAMS')
```

Et je peux finalement créer mon fichier source, ouvrant l'éditeur de texte __SEU__ (__STRSEU - STaRt Source Entry Utility__):

```
STRSEU SRCFILE(MYLIB/QCBLSRC) SRCMBR(HELLOWORLD) TYPE(CBL) OPTION(2) TEXT('HELLO WORLD IN COBOL')
```

Le programme __Cobol__ qui me permet d'effectuer le POC est le suivant:

```
       IDENTIFICATION DIVISION.
       PROGRAM-ID HWCBL.

       ENVIRONMENT DIVISION.

       DATA DIVISION.
       WORKING-STORAGE SECTION.

       PROCEDURE DIVISION.
         DISPLAY "HELLO WORLD!".
         STOP RUN.
```

Le code est plutôt simple, il affiche "HELLO WORLD!". Il reste maintenant à le compiler et à l'exécuter. Cela se fait de la même manière que tout langage compilé. Il faut créer un module objet, puis le lié avec les différentes library, module, etc. Il est à noter que le __Cobol__ que j'utilise est l'__ILE Cobol__ (__ILE - Integrated Language Environment__), c'est à dire qu'il est possible de fabriquer un programme unique à partir de différent programme __Cobol__, mais aussi d'y ajouter des programme __Rexx__ par example, ou __C__, ou du __JCL__. Cela offre une maneuvrabilité très importante dans la conception d'un programme.

La __CL command__ utilisée pour compiler le programme est la suivante:

```
CRTBNDCBL PGM(MYLIB/HWCBL) SRCFILE(MYLIB/QCBLSRC) SRCMBR(HELLOWORLD) OUTPUT(*PRINT) TEXT('HELLO WORLD IN COBOL')
```

Il est possible de regarder les différentes erreurs de compilation ou messsages afficher durant la compilation en utilisant les commandes suivantes:

```
DSPJOB ---> puis regarder le ficher de spool (4)
WRKJOB
WRKOUTQ queue-name
WRKSPLF
```


Pour exécuter mon programme, j'utilise la __CL command__ suivante:

```
CALL PGM(MYLIB/HWCBL)
```

Une exécution d'un programme s'appelle un __JOB__. Lorsque l'on a soumis le __job__, nous n'avons pas vu "HELLO WORLD!" s'afficher. Pour regarder la sortie du programme, il faut que je regarde dans les __log__ du __job__. La __CL command__ qui permet cela est (__DSPJOBLOG - DiSPlay JOB LOG__):

```
DSPJOBLOG
```

Il faut ensuite choisir le __job__ et appuyer sur __F10__ pour l'afficher puis utiliser les flèches __scroll up/ scroll down__ pour naviguer dans les logs:

![image alt text](/images/mainframe/as400/HWCBL-log.png)

Sur ce screenshot, on y voit les commandes que j'ai exécuté ainsi que les erreurs associées. Les erreurs associées à la commande __CALL__:

```
Bibliothèque QCBLSRC non trouvée
Erreur trouvée dans la commande CALL
```

Et à la fin, lorsque la commande est bien exécutée, on y voit notre "HELLO WORLD!".

On peut noter en passant, que l'ensemble des commandes exécutées se trouve dans les __logs__ ...

Comme je l'ai déjà énoncé, nous sommes connectés en __TELNET__, ce qui signifie que les données circulents en clair ... On peut voir sur le screenshot ci-dessous ma commande __CALL__ . On voit aussi que je peux retrouver le code source de mon programme lorsque je demande à l'éditer ... Pour pouvoir lire le contenu des trames réseaux, il faut passer l'encodage des caractères de __ASCII__ à __EBCDIC__ car l'AS400 utilise cet encodage.

![image alt text](/images/mainframe/as400/HWCBL-telnet.png)

Cela signifie qu'il est possible pour un attaquant de sniffer le traffic réseau. Ainsi il peut récupérer le couple login/password lorsque quelqu'un se connecte et donc l'usurper ensuite pour se connecter à l'AS400. Mais il est également possible de simplement récupérer le nom d'utilisateur et de faire l'hypothèse que le mot de passe est le même que le nom d'utilisateur (ce qui arive très souvent sur ces systèmes).

# CLP

Pour écrire un programme en __CL__, c'es-à-dire un __CLP__, il faut que je créer un nouveau __file__ qui contiendra mes codes sources __members__:

```
CRTSRCPF FILE(MYLIB/QCLSRC) TEXT('MY COBOL PROGRAMS')
STRSEU SRCFILE(MYLIB/QCLSRC) SRCMBR(HELLOWORLD) TYPE(CL) OPTION(2) TEXT('HELLO WORLD IN CL')
```

Un __CLP__ est grosso-modo l'équivalent d'un programme bash. Il regroupe les différentes commandes __CL__ au sein d'un fichier que l'on pourra rendre exécutable.

Le programme que je créer est le suivant:

```
PGM
  SNDPGMMSG MSG('HELLO WORLD')
ENDPGM
```

La commande __CL__ __SNDPGMMSG__ (__SeNDProGraMMeSsaGe__) permet d'envoyer un message sur la console.

Pour le compiler et l'exécuter, j'utilise les commandes __CL__ suivantes:

```
CRTBNDCL PGM(MYLIB/HWCL) SRCFILE(MYLIB/QCLSRC) SRCMBR(HELLOWORLD) OUTPUT(*PRINT) TEXT('HELLO WORLD IN CL')
CALL PGM(MYLIB/HWCL)
```

Le résultat est présenté ci-dessous:

![image alt text](/images/mainframe/as400/HWCL-result.png)

