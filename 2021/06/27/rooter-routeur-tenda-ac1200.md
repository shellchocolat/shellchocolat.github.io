# Rooter son routeur (Tenda ac1200)

On va voir ici comment rooter un routeur __Tenda AC1200__ à partir d'un port série (__UART__). Le routeur ressemble à ceci:

![image alt text](/images/router-tenda-ac1200-mu-mimo/IMG_20210626_082437701.jpg)

Une fois démonté, le PCB ressemble à:

![image alt text](/images/router-tenda-ac1200-mu-mimo/IMG_20210626_082437701.jpg)

L'important est d'identifier les composants les plus importants. Parmi ceux-ci:

* en haut, en jaune, une connectique ethernet (c'est un routeur ..)

* en dessous, en noir, 2 JDX G3604D. Ce sont des modules magnétiques 1000 Base-T qui permettent de supporter les connections Gigabits et s'interface avec la connectique ethernet au dessus. La seule doc que j'ai pu trouver pour ce composant: https://datasheet.lcsc.com/szlcsc/1908071506_CND-tek-G3604D_C408884.pdf

* en dessous, la grosse plaque noire (RTL8367RB), permet de manager les flux provenant des modules magnétiques 1000 Base-T. La documentation: https://datasheetspdf.com/pdf-file/1461443/Realtek/RTL8367RB/1

* encore en dessous, protégé par un radiateur, probablement le microcontroleur

* à sa droite, la petite plaque noire (RTL8812BRH), est un controleur WLAN 802.11ac/abgn. Je ne trouve pas de documentation dessus.

Apparemement il n'y a pas de puce permettant de stocker le firmware. Etrange ... Il faut regarder sous le PCB:

![image alt text](/images/router-tenda-ac1200-mu-mimo/IMG_20210626_083056215.jpg)

On y voit une seule puce:

* une Winbond W25Q64JV qui est une flash SPI: https://docs.rs-online.com/5be0/0900766b81703f85.pdf

Cette puce permet de stocker le firmware et communique en suivant le protocole __SPI__. 

Une fois que l'on a compris le fonctionnement de la majorité des composants, il faut chercher des ports de debug. On voit sur la première image du PCB, en bas à gauche, 4 pins. C'est moi qui les ai soudés pour pour me connecter dessus plus facilement. Il s'agit des pins associés à l'__UART__.

L'UART fonctionne simplement. Il y a un pin d'écriture __TX__ et un pin de lecture __RX__. Les 2 autres pins sont la __masse__ et l'__alimentation__. Il est important d'identifer quel pin correspond à quoi de manière à ne pas griller la carte ou notre outil qui sera connecté dessus.

Pour identifier les pins, il existe différentes méthodes. On peut utiliser un multimètre, ou bien essayer de comprendre les composants qui sont autours de ces pins.

Ci-dessous une vue clair du port de débug UART:

![image alt text](/images/router-tenda-ac1200-mu-mimo/IMG_20210626_083259482.jpg)

Je vais commencer par établir une hypothèse concernant les pins que je vérifierais ensuite à l'aide du multimètre.

* Tout d'abord on remarque qu'un composant est soudé sous chaque pins excepté sous celui qui est à droite (le pin 4). 

* Sous le pin 1, je vois un condensateur __C122__. 

* Sous le pin 2, je vois une resistance __R90__.

* Sous le pin 3, je vois une resistance __R91__.

Par symétrie entre les pins RX et TX, je peux estimer qu'il s'agit des pins 2 et 3 ou 3 et 2. En ce qui concerne le pin 1 (qui est associé à un condensateur), je peux en déduire qu'il s'agit de l'alimentation, car le condensateur va permettre de lisser le courant et ainsi limité les variations éventuelles de courant. Le pin 4 qui n'est relié à rien est la masse évidemment.

On peut vérifer cela aisément à l'aide du multimètre. En commençant par la masse, il suffit de mettre le multimètre en mode __continuité__ (qui bip quand le courant passe). On met un fil du multimètre sur le pin 4 et l'autre sur un élément métalique d'un des boutons par exemple. Toutes les masses devant être reliée, on doit entendre le multimètre bipper. C'est bien le cas, on a trouvé la masse.

Pour vérifier l'alimentation, il faut mettre l'appareil en marche, mettre un fil du multimètre sur la masse que l'on vient de trouver, et l'autre sur le pin 1. On remarque que la tension est de __3.3V__ sans fluctuation: merci le condensateur !

Pour vérifier les pins 2 et 3, ce sera par l'expérience. On va brancher un __Hydrabus__ sur le port de débug, et si l'on voit des choses s'afficher ce la signifie que l'on arrive bien à lire sur le pin __RX__, sinon c'est il faut inverser les branchements. Ce n'est pas critique de se trouver sur __RX__ et __TX__. En revanche ca l'est sur les pins de __masse__ et d'__alimentation__ car cela peut griller notre carte Hydrabus.

Pour l'expérience, nous n'avons pas besoin de brancher l'alimentation, car on va utiliser l'alimentation fournie par le routeur. Si l'on branche l'alimentation, on risque d'avoir 2 fois plus de puissance et donc de griller le condensateur, et donc de griller le routeur ...

De manière général, on utilise soit l'alimentation du routeur, soit l'alimentation de l'Hydrabus, pas les 2. L'alimentation du routeur est plus stable, on utilisera donc celle là.

Une photo du montage branché est présenté ci-dessous:

![image alt text](/images/router-tenda-ac1200-mu-mimo/IMG_20210626_090313628.jpg)

Comment trouver les pins sur l'Hydrabus? Easy, il suffit de le mettre en mode UART et de taper __show pins__:

![image alt text](/images/router-tenda-ac1200-mu-mimo/show_pin.png)

Lorsque j'alimente le routeur avec l'Hydrabus branché (rappel: ne pas brancher l'alimentation), je vois bien du texte s'afficher. Le texte est lisible parceque j'ai choisi le bon baudrate. Il est modifiable facilement sur l'Hydrabus par la commande __speed 115200__:

![image alt text](/images/router-tenda-ac1200-mu-mimo/conf.png)

Et le texte accessible depuis le port UART est le suivant:

![image alt text](/images/router-tenda-ac1200-mu-mimo/boot.png)

Là, on sent qu'on a gagné !!! En fait non !!! Sur de nombreux appareil embarqué du commerce, on obtient un shell root directement en se branchant en UART, mais dans le cas présent, un mot de passe nous est demandé comme on peut le voir ci-dessous:

![image alt text](/images/router-tenda-ac1200-mu-mimo/login_incorrect.png)

J'ai testé les mots de passe usuels: admin, tenda, administrator, 12345, 123456789 and so on ... Il faut donc aller un peu plus loin. On a vu que la puce qui contient le firmware communique en SPI, on peut envisager de dumper le firmware et de l'analyser, ou on peut d'abord tenter de le récupérer sur internet sur le site du fournisseur !

Et en effet, le firmware est disponible sur le site du fournisseur:

* https://www.tendacn.com/fr/download/detail-3427.html

![image alt text](/images/router-tenda-ac1200-mu-mimo/download_firmware.png)

Une fois téléchargé, puis dézippé, on peut l'analyser avec __binwalk__ pour voir ce qu'il contient:
```
➜  tenda-1200 binwalk US_AC1200V1.0RTL_V15.03.06.23_multi_TD01.bin 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
10328         0x2858          LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 7070932 bytes
1068530       0x104DF2        MySQL ISAM index file Version 6
2105426       0x202052        Squashfs filesystem, little endian, version 4.0, compression:xz, size: 3700854 bytes, 810 inodes, blocksize: 131072 bytes, created: 2038-04-24 02:46:24
```

On voit que c'est du squashfs, on va l'extraire afin de pouvoir naviguer dans le système de fichiers:
```
➜  tenda-1200 binwalk -eM US_AC1200V1.0RTL_V15.03.06.23_multi_TD01.bin

Scan Time:     2021-06-26 09:24:40
Target File:   /home/shellchocolat/FIRMWARE/tenda-1200/US_AC1200V1.0RTL_V15.03.06.23_multi_TD01.bin
MD5 Checksum:  4d8877c86261ed5b195da70b4b332f82
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
10328         0x2858          LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 7070932 bytes
1068530       0x104DF2        MySQL ISAM index file Version 6
2105426       0x202052        Squashfs filesystem, little endian, version 4.0, compression:xz, size: 3700854 bytes, 810 inodes, blocksize: 131072 bytes, created: 2038-04-24 02:46:24


Scan Time:     2021-06-26 09:24:42
Target File:   /home/shellchocolat/FIRMWARE/tenda-1200/_US_AC1200V1.0RTL_V15.03.06.23_multi_TD01.bin.extracted/2858
MD5 Checksum:  f3efd4ef20f16139ee83fb64b9b711e8
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
4653072       0x470010        Linux kernel version 3.10.9
4769712       0x48C7B0        SHA256 hash constants, little endian
5353032       0x51AE48        xz compressed data
5363336       0x51D688        Unix path: /lib/firmware/updates/3.10.90
5546566       0x54A246        Neighborly text, "neighbor %.2x%.2x.%pM lost rename link %s to %s"
5552991       0x54BB5F        HTML document header
5553154       0x54BC02        HTML document footer
5686784       0x56C600        CRC32 polynomial table, little endian
5790241       0x585A21        Intel x86 or x64 microcode, sig 0x0205080d, pf_mask 0x14191e21, 1B1E-12-17, rev 0x1f000000, size 1
5790257       0x585A31        Intel x86 or x64 microcode, sig 0x0305090e, pf_mask 0x161c2225, 1E21-14-19, rev 0x22000000, size 1
5790577       0x585B71        Intel x86 or x64 microcode, sig 0x0205080d, pf_mask 0x14191e21, 1B1E-12-17, rev 0x1f000000, size 1
5790593       0x585B81        Intel x86 or x64 microcode, sig 0x0305090e, pf_mask 0x161c2225, 1E21-14-19, rev 0x22000000, size 1
6066896       0x5C92D0        AES S-Box
```

On a donc accès au système de fichiers:

![image alt text](/images/router-tenda-ac1200-mu-mimo/squashfs_root.png)

Et on a donc accès au fichier etc/passwd:

![image alt text](/images/router-tenda-ac1200-mu-mimo/etc_passwd.png)

Et au fichier etc/shadow:

![image alt text](/images/router-tenda-ac1200-mu-mimo/etc_shadow.png)

On voit que seul l'utilisateur __root__ a un mot de passe d'après le fichier /etc/shadow. Hum le hash de root est un $1$ ce qui signifie MD5, ca devrait se casser facilement grâce à __hashcat__:
```
$ hashcat -m 500 -a 0 ~/h.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

![image alt text](/images/router-tenda-ac1200-mu-mimo/hashcat.png)

Et le mot de passe est cassé en moins d'une minute \\(^.^)//

On retourne se connecter en UART sur le routeur et on fournis maintenant le mot de passe root, et ... Victoire ! On a un accès root sur l'appareil en cours de fonctionnement ! On y voit des binaires intéressants comme par exemple:

* alibaba_update

* tendaupload

* UDPserver

* chat

* auth

* monitor

* logserver

* et cetera

Mais bref, on a aussi accès à ces binaires grâce au firmware que l'on a téléchargé. On va donc pouvoir les analyser pour trouver "d'éventuelles" vulnérabilités.

A titre d'exemple, un __grep__ sur le système de fichiers donne:

./webroot_ro/goform/cloud.txt:"password":"NjE3MzA1NjI=",
./webroot_ro/goform/getWanParameters.txt:"vpnPwd": "password",
./webroot_ro/goform/GetPptpClientCfg.txt:"password":"456",
./webroot_ro/goform/GetSambaCfg.txt:"password":"1asdf23",
./webroot_ro/goform/GetPptpServerCfg.txt:"password": "123456789",
./webroot_ro/goform/GetPptpServerCfg.txt:"password": "123456789",
./webroot_ro/goform/GetPptpServerCfg.txt:"password": "123456789",
