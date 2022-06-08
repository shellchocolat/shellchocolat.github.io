# Smart Contract - basic

Un __smart contract__, c'est comme un __smart phone__. Un smart phone, c'est un téléphone "intelligent" qui peut faire des choses que ne peut pas faire un téléphone "classique". Dans le cas d'un __smart contract__, il s'agit d'un contrat "intelligent" qui peut donc faire des choses qu'un contrat "classique" ne peut pas faire.

Un contrat "classique", c'est un bout de papier figé une fois signé dans lequel sont indiqués les termes du contrat. Ce type de contrat, vous en avez tous signés. Vous avez fait un emprunt pour votre voiture, vous avez un compte bancaire, une carte bleue, etc.

Un __smart contract__ est "intelligent" car il peut faire des choses qu'un contrat "classique" ne peut pas faire. En effet, un __smart contract__ n'est pas un bout de papier, c'est du code qui contient des fonctions qui peuvent être appelées ou non par les propriétaires du contrat.

Un example de __smart contract__ est présenté ci-dessous:

```
contract HelloWorld {
  function helloworld() public returns (bool){ 
    return true;
  }
}
```

Ce contrat ne régit rien, il se contente de retourner __True__ à chaque fois que la fonction __helloworld()__ est appelée. Il peut y avoir plusieurs fonctions dans un __smart contract__ qui font différentes choses, comme ajouter de l'__ether__, retirer de l'__ether__, communiquer avec un autre __smart contract__ etc. 

Les contrats "classiques" sont relus de nombreuses fois par des juriste pour s'assurer qu'ils ne possèdent pas de faille. Il devrait en être de même pour les __smart contract__. Cependant, un __smart contract__ c'est du code. Tout le monde ne lit pas le code.

En parlant de code. Il existe différent langages utilisés pour coder les __smart contracts__. Par example, __Solidity__ est le langage de programmation utilisé pour les __smart contracts__ de la platforme __Ethereum__.

Qui dit code, dit machine qui exécute le code. Le code d'un __smart contract__ est exécuté sur une machine virtuelle. Commme il s'agit ici de __Solidity__, la machine virtuelle utilisée est celle de la platforme __Ethereum__ qui se nomme __EVM__ (Ethereum Virtual Machine). Il existe donc un langage assembleur ... hum hum (ça j'aime !)

Il existe des fonctions dites "public" qui peuvent être appelées par les utilisateurs du contrat, et des fonctions dites "private" qui ne peuvent être utilisées qu'en interne. Il existe des __variables__ de différents __types__. Bref c'est un vrai langage de programmation. Certes récent, mais fonctionnel ! Qui dit langage récent, dit possibles bugs. A vous de les trouver, il y en a j'en suis certain !

Pour soumettre un contrat sur la blockchaine, il faut le compiler. Eh oui, c'est du code ! Le compilateur de __Solidity__ est __solc__. Cependant, il peut aussi être compilé directement sur la blockchaine si celle-ci embarque le compilateur. Dans ce cas, il faut lui soumettre le code. Dans le cas du __smart contract__ présenté ci-dessus:

```
$ curl -X POST --data '{"jsonrpc":"2.0","method":"eth_compileSolidity","params":["contract HelloWorld {event Print(string out);function(){Print("Hello, World!");}}"],"id":1}' http://127.0.0.1:8100
```

J'ai utilisé l'outil __curl__ pour soumettre mon contrat à la blockaine hébergée en local sur le port 8100. J'ai appelé la méthode __eth_compileSolidity__ pour demander la compilation de mon __smart contract__.

Pour pouvoir utiliser un __smart contract__, il faut un "compte utilisateur". J'utilise __metamask__ pour le "contenir". Mon compte est protégé par une clef de 12 mots aléatoires associés à un mot de passe. Si je ne connais pas ces mots ni le mot passe, je ne peux pas débloquer le compte. Chaque compte est libre d'accès en lecture sur la blockchaine. Pour pouvoir consulter un compte, il faut connaitre son adresse, il s'agit d'un hash. Sur la blockchaine de test __Ropsten__, j'ai 5 ether, sur la blockchaine principale, j'en ai 0. L'adresse que j'utilise pour cela est: __0x1d469fcc843653a777e006561b199839ccca39f6__

Si je veux connaitre le montant que j'ai sur la blockchaine __Ropsten__, je vais utiliser la commande suivante:

```
curl --data '{"jsonrpc":"2.0","method":"eth_getBalance", "params": ["0x1d469fcc843653a777e006561b199839ccca39f6", "latest"], "id":1}' https://ropsten.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161
```

J'ai utilisé la méthode __eth_getBalance__, et j'obtiens le résultat suivant:

```
{"jsonrpc":"2.0","id":2,"result":"0x454a00542f787a65"}
```

Le résultat est le nombre d'ether en hexadécimal retourné en __wei__. Pour le convertir en __ether__, je convertis le résultat en décimal: __4992803498467293797 wei__, puis je décale la virgule de __18__. Le __wei__ est donc une sous unité de l'ether (équivalent euro, centime). J'ai donc en réalité __4.992803498467293797 ether__

Tout à l'heure j'ai compilé en local parcequ'il y avait un compilateur disponible. Sur la blockchaine de test __Ropstein__ il n'y en a pas. Pour savoir si la blockchaine possède un compilateur, on peut utiliser la méthode __eth_getCompilers__:

```
curl --data '{"jsonrpc":"2.0","method": "eth_getCompilers", "id": 1}' https://ropsten.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161
```

Pour soumettre un contrat sur la blockchaine, il faut payer des frais. Les frais s'appelle des __gas__. On peut les voir comme une manifestation de l'entropie. La soumission d'un contrat va augmenter l'entropie du sytème, il faut payer pour cela. Les frais vont dépendre directement du contrat. Pour les estimer, il faut soumettre le contrat compilé et appeler la méthode __eth_estimateGas__. Pour obtenir le bytecode du contrat, j'utilise le compilateur __solc__ comme ci-dessous:

```
./solc-static-linux --bin hello.sol

======= hello.sol:HelloWorld =======
Binary:
608060405234801561001057600080fd5b5060b88061001f6000396000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c80632f2f485914602d575b600080fd5b60336047565b604051603e91906069565b60405180910390f35b60006001905090565b60008115159050919050565b6063816050565b82525050565b6000602082019050607c6000830184605c565b9291505056fea264697066735822122033f125a08f4abc461ae776af51c3e5d50d9e294d0ce3829ad7578cba78df903e64736f6c634300080e0033
```

Puis, pour estimer les frais:

```
curl --data '{"jsonrpc":"2.0","method": "eth_estimateGas", "params": [{"from": "0x1d469fcc843653a777e006561b199839ccca39f6", "data": "0x608060405234801561001057600080fd5b5060b88061001f6000396000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c80632f2f485914602d575b600080fd5b60336047565b604051603e91906069565b60405180910390f35b60006001905090565b60008115159050919050565b6063816050565b82525050565b6000602082019050607c6000830184605c565b9291505056fea264697066735822122033f125a08f4abc461ae776af51c3e5d50d9e294d0ce3829ad7578cba78df903e64736f6c634300080e0033"}], "id": 1}' https://ropsten.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161

{"jsonrpc":"2.0","id":1,"result":"0x16be7"}
```

Les frais sont donc de __0x16be7 wei__, soit __0.000000000000093159 ether__.

On peut ensuite deployer le contrat sur la blockchaine en utilisant la méthode __eth_sendTransaction__:

```
curl --data '{"jsonrpc":"2.0","method": "eth_sendTransaction", "params": [{"from": "0x1d469fcc843653a777e006561b199839ccca39f6", "gas": "0x16be7", "data": "0x608060405234801561001057600080fd5b5060b88061001f6000396000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c80632f2f485914602d575b600080fd5b60336047565b604051603e91906069565b60405180910390f35b60006001905090565b60008115159050919050565b6063816050565b82525050565b6000602082019050607c6000830184605c565b9291505056fea264697066735822122033f125a08f4abc461ae776af51c3e5d50d9e294d0ce3829ad7578cba78df903e64736f6c634300080e0033"}], "id": 1}' http://127.0.0.1:8100
```

Pour ensuite récupérer l'adresse à laquelle se situe le contrat, il faut utiliser la méthode __eth_getTransactionReceipt__.

Tout cela est un peu fastidieux à faire à la main. On peut alors utiliser un __IDE__ spécialisé. Le plus connu est __Remix-ide__. Il est possible de coder les __smart contracts__, de les valider, puis de les déployer, d'intéragir avec eux, et même de les débugger: __https://remix-project.org/__

Je recommande d'utiliser la version __desktop__ pour une blockchaine en local, mais pour une blockchaine de test comme __Ropstein__ ou la blockaine principale __Ethereum__, il vaut mieux utiliser la version __online__ car cela permet de se connecter directement avec __Metamask__ et donc de pouvoir intéragir avec les __smart contracts__ sur __Ropstein__. 

Finalement, interagir avec un __smart contrat__, c'est comme intéragir avec une __API__. Il y a différent __endpoints__ qui correspondent aux différentes fonctions publiques du __smart contract__. 

Pour appeler une fonction du __smart contract__, il faut la lui demander avec la méthode __eth_sendTransaction__ ou directement avec __Remix-ide__ qui fera la même chose. J'explique briévement le principe, mais sachez que __Remix-ide__ fera tout tout seul comme un grand.

La fonction que je veux appeler est __helloworld()__. Elle ne prend aucun paramètre. Il faut que je calcule le hash __keccak256__ de __helloworld()__. Cette fonction cryptographique calcul un hash qui est déjà calculé par ailleur par la __EVM__. Elle connait donc la correspondance avec la fonction __helloworld()__ vu qu'on lui a déjà soumit le contrat.

Quand je dis que je calcule le hash de __helloworld()__, c'est au sens litéral du terme. Je fais (pseudo-code):

```
keccak256("helloworld()")
```

Oui, la string __helloworld()__. Si j'avais un paramètre pour cette fonction, j'aurais fait:

```
keccak256("helloworld(uint8)")
```

J'utilise __cyberchef__ (https://gchq.github.io/CyberChef/), pour calculer rapidement ce hash __keccak256__ et j'obtiens:

```
0x946378a94bcdb681239d801e5f871d6326df61035c6f6dd48372823a2905fd8e2d1e82194b58d53fc8dba7b54cfdd570327e7d12538e93bfb79162a086a70a02
```

Une fois que j'ai ce hash, j'en prend les 4 premiers bytes: __0x946378a9__, et je les soumets à __0xAdresseDeMonContrat__:

```
curl --data '{"jsonrpc":"2.0","method": "eth_sendTransaction", "params": [{"from": "0x1d469fcc843653a777e006561b199839ccca39f6", "to": "0xAdresseDeMonContrat", "data": "__0x946378a9__"}], "id": 1}' localhost:8100
```

Si j'avais eu un paramètre, il aurait fallu les passer sur une valeur de __256 bits__ (la blockchaine ethereum ne fonctionne bien qu'avec des valeurs de 256 bits). Par exemple, 12 est un uint8, il vaut en hexadécimal 0x0C que je convertis en 256 bits: __000000000000000000000000000000000000000000000000000000000000000C__. Je prend cette valeur, je l'accole au "hash tronqué" de ma fonction __helloworld(uint8)__: __0x41b37624__ et j'obtiens la __data__ suivante:

```
0x41b37624000000000000000000000000000000000000000000000000000000000000000C
```

Si j'avais eu un second paramètre à ma fonction, il aurait fallu que je mette ce second paramètre au format 256 bits, puis que je l'accole à la valeur ci-dessous (sans oublier de recalculer la valeur du "hash tronqué" de la fonction __helloworld(uint8, uint8)__ par example).

Pour ceux qui veulent aller plus loin, la documentation Ethereum est un __must read__: __https://ethdocs.org/en/latest/__


