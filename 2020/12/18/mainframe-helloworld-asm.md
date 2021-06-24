
Vous savez comme j'apprécie de coder en assembleur. Que ce soit sur un linux ou un windows, j'adore me plonger dans le langage machine. Je ne vais pas faire exception sur z/OS. Pour rappel, __z/OS__ est un des OS qui tourne sur __Mainframe__. Je dis "un des OS" car il y en a plusieurs: z/OS, USS, z/VM, z/VSE, z/TPF. L'OS standard et le plus utilisé est __z/OS__. L'assembleur qui est utilisé sur __z/OS__ est l'__HLASM__ pour __High Level ASseMbler__.

De fait, les mnémoniques ne sont pas les mêmes que ce que l'on a pu voir jusqu'ici. De nombreux éléments sont similaires à ce que l'on trouve sur x86/64 et de nombreux autres sont différents. Par exemple, les charactères "printables" (a-zA-Z0-9) ne sont pas consécutifs. Sur x86/64, les bytes les représentants vont de __x61__ à __x7A__ (a-z) et sont consécutifs, tandis que sur __HLASM__ les bytes les réprésentants vont de __x81__ à __x89__ (a-i), puis de __x91__ à __x99__ (j-r), puis de __xA2__ à __A9__ (s-z) et sont donc non consécutifs.

De plus, contrairement à l'assembler x86/64, l'alignement ne se fait pas sur un __mot__ (4 bytes), mais sur un demi-mot (2 bytes). C'est un point très important, ceux qui ont déjà développés quelques __exploits__ le savent bien !

J'ai pu trouver quelques codes d'hello world en __HLASM__, mais aucun ne fonctionnaient. Les procédures utilisées pour compiler et linker le code n'étaient pas présentes sur le mainframe que j'avais à disposition. Ce sont des choses qui arrivent ... Il a fallu quasiment tout refaire de la base afin que cela puisse fonctionner sur n'importe quel z/OS du moment que le compilateur et le linkeur sont disponibles.

Le compilateur s'appelle __ASM90__ et le linker s'appelle __HEWL__.

Dans les différents __Hello World__ que vous pourrez trouver, vous ne verre pas d'appel explicite à ces programmes, mais vous aurez:

```JCL
//STEP1   EXEC PROC=ASMACLG
```

Il faut savoir que pour compiler, linker, exécuter un programme sur z/OS, il faut soumettre un __job__. Ce job est soumis grâce à un __JCL__  (__Job Control Language__). La ligne de code présenté ci-dessus est un extrait d'un __JCL__ qui permet d'appeler la procédure __ASMACLG__. J'appelle donc une procédure qui permet de __Compiler__, __Linker__, et __Executer__ (__CLG__: __Compile__, __Link__, __Go__), et je ne fais donc pas explicitement appel au programme __ASM90__ et __HEWL__. C'est bien pratique, ca réduit la taille du __JCL__, mais ça cache beaucoup de choses sous le tapis. De plus, si cette procédure n'existe pas, ... bah on peut pas exécuter du code __HLASM__ ! Faux! Il suffit de refaire ce que fait la procédure !

On se rend compte que pour exécuter du code __HLASM__, il ne suffit pas de coder en __HLASM__, mais il faut aussi connaitre le __JCL__.