# Reverse Engineering - Univers - 450pts

**Univers** est le nom d'un challenge de **Reverse Enginnering** vallant **450 points**.  
J'ai obtenu **15 points bonus** pour avoir flag le challenge le premier.

Le challenge a été validé au total par 4 personnes.

Voici l'énoncé :

Pour valider cette épreuve, vous devez soumettre la ligne de commande  
avec ses arguments dans l'interface.
Par exemple, si la ligne de commande `Univers.exe a b c d` valide  
l'épreuve, celle-ci sera le flag.

On nous fournit un binaire nommé **Univers.exe**.

## Description et objectifs du challenge

Le binaire fourni est un fichier exécutable PE 64 bits.

L'objectif du challenge est de résoudre une équation en fournissant une solution au travers des arguments dans la ligne de commande.  
Cependant, les valeurs solutions de l'équation ne sont pas des entiers représentables avec 64 bits.  

Pour manipuler de grands entiers, le programme implémente l'objet BigInteger.  
Cela consiste à manipuler de grands nombres au travers de chaines de caractères.

Une librairie très connue réalisant cela est GMPLIB (GNU Multiple Precision Arithmetic Library).  
Je recommande de regarder un peu comment fonctionne la librairie afin de mieux comprendre le code désassemblé ou décompilé.

Voici, un exemple simple avec GMP :

```c
mpz_t n;   // déclaration de la variable
mpz_init(n);   // initialisation de la variable
mpz_set_str(n,"1234");   // assignation par une chaîne de caractère
mpz_clear(n);   // libération de l'espace
```

Voilà maintenant vous en savez suffisamment pour comprendre 75% du binaire,  
car ces fonctions sont omniprésentes dans le binaire à analyser.  

Comme le type BigInteger n'est pas un type standard, toutes les opérations classiques comme l'assignation, l'addition, la multiplication ...,  
nécessitent d'être réimplémentées.

Une première étape du challenge va être d'identifier les fonctions utilisées et de les renommer.


## Identification des fonctions

J'utilise Ghidra afin de désassembler et décompiler le programme.  
Dans cette partie, je me contente d'expliquer comment j'ai identifié certaines fonctions.
Les fonctions sont renommées selon la logique de  nommage de GMPLIB même si cela n'est pas la librairie utilisée pour compiler le binaire.
Attention, l'ordre des paramètres peut être différents comparé à la vrai librairie.
Les paramètres sont passés par les registres : RCX, RDX, R8


- **mpz_set_str(mpz_t dest, char * source, int length)**  
La fonction en **0x140009a40** est la fonction **mpz_set_str**, on peut le voir grâce à la ligne `memcpy(_Dst,param_2,(size_t)param_3);`.

- **mpz_set_str_ui(mpz_t dest, int source)**  
La fonction en **0x140001fa0** est la fonction **mpz_set_str_ui**, on peut le voir grâce aux instructions de **0x140002040** à **0x140002068**  
permettant de convertir un nombre en chaîne de caractère.

- **mpz_set(mpz_t dest, mpz_t * source)**  
La fonction en **0x1400095c0** est la fonction **mpz_set** d'un mpz_t vers un autre mpz_t.

- **mpz_mul(mpz_t op1, mpz_t dest, mpz_t op2)**  
La fonction en **0x140004750** est la fonction **mpz_mul**, on peut  facilement le voir grâce à la gestion des cas où l'une des opérandes vaut 0 ou 1.

- **mpz_add(mpz_t op1, mpz_t dest, mpz_t op2)**  
La fonction en **0x140003790** est la fonction **mpz_add**, si op1>0 et op2<0 alors appelle mpz_sub(op1, dest,abs(op2)).

- **mpz_sub(mpz_t op1, mpz_t dest, mpz_t op2)**  
La fonction en **0x140003f60** est la fonction **mpz_sub**.


## Analyse du programme

A partir des résultats de la partie précédente j'ai écrit un pseudo-code éclairant le fonctionnement du programme :

```python
def fact(n): # factorielle de n

def child_computation(value, counter):
  srand(time(0))
  if counter & 1 ==1:
    random_number = rand()
    if random_number & 1 ==0: # le résultat est le même quelque soit la valeur
      child_result = value**3 + counter * 121645100408832000
    else:
      child_result = value**2 * value + counter * 121645100408832000
  else: # ce résultat n'est pas utilisé dans le résultat final
      child_result = sqrt(value) + counter * 1203231203128331
  return child_result

def function_with_fork(value, counter):
  r, w = os.pipe()
  os.fork()
  if child_process:
    child_result = child_computation(value, counter)
    w.write(child_result)
    exit()
  if parent_process:
    fork_result = w.read()
    return fork_result
    

def main():
  counter = 0
  while counter <= 5:
    value = atoll(argv[counter])
    fork_result = function_with_fork(value,counter)
    factorial_19 = fact(19)
    iteration_result = fork_result - ( factorial_19 * counter)
    if (counter & 1 !=0): #Si impair
      global_result = global_result + iteration_result
  return 0
    
```

Le programme demande 5 arguments mais seuls les arguments de numéro impair (donc le 1, le 3 et le 5) sont pris en compte dans les calculs.
Par conséquent, on peut déjà dire que la solution est de la forme : `Univers.exe value1 0 value3 0 value5`.

Sachant cela et sachant que `19! = 121645100408832000`, de nombreuses simplifications peut être faites.  
La valeur de `global_result` lorsque l'on quitte la fonction `main` vaut : `value1 ^ 3 + value3 ^ 3 + value5 ^ 3`.

Il s'agit donc d'une somme de trois cubes.
Problème: Le programme quitte la fonction `main` sans vérifier si le résultat est vrai ou faux.

Il doit donc y avoir une fonction qui s'exécute après la fonction `main`.

## Fonction exécutée après main

Avant d'exécuter la fonction `main`, le programme réalise un certain nombre d'initialisations comme par exemple préparer l'accès aux arguments de la ligne de commande.

On peut remarquer à l'entrypoint l'utilisation de la fonction `_initterm`, qui prend en paramètre deux adresses. Toutes les valeurs qui sont stockées entre ces deux adresses sont considérées comme des adresses de fonctions devant être exécutées avant la fonction `main`.

Dans notre cas, un certain nombre de fonctions s'exécutent avant la fonction `main`.  
On peut par exemple citer la fonction en **0x140001000** qui initie la valeur de `global_result` à 0.

La plupart des fonctions exécutées avant la fonction `main` appellent la fonction en **0x14000ab08** avec en argument l'adresse d'une autre fonction.
L'analyse de cette fonction montre qu'elle fait appel à la fonction `atexit`. La fonction passée en paramètre est alors exécutée après la fonction `main`.

Ainsi, un certain nombre de fonctions pourront s'exécuter après la fonction `main`.
Parmi ces fonctions deux nous intéressent :
- la fonction en **0x14000c3f0** qui affiche le message d'échec.
- la fonction en **0x140008b30** qui réalise la comparaison finale et affiche le message de succès.

Voici un pseudo-code assez simplifié de ce qui se passe une fois la fonction `main` terminée :

```python
def path_check():
  absolute_path = GetModuleFileName()
  # début version très simplifiée du programme
  backslach_count = count_backslash(absolute_path)
  path_length= len(absolute_path)
  value1 = backslach_count + 2
  value2 = path_length - backslach_count + 1
  # fin version très simplifiée du programme
  value3 = (value1 + 1) * value1
  if (value2 != value3) or (value3 != 7 * value1):
    exit() # si le chemin du fichier est incorrect, le programme quitte sans rien afficher
  return value2
 
 
def exit_main_function():
  expected_value = path_check()
  if global_result == expected_value:
    print("0K")
    exit()
  print("You are lost !")
  return
```

On constate que la valeur de `global_resutl` est comparée à une valeur attendue.
Mais pour cela il faut que le chemin absolu du programme soit correct.

On a un système d'équation très facile à résoudre.

`value1` doit valoir 0 ou 6 afin que `value3 == 7 * value1`.   
La valeur 0 est impossible car sinon `backslash_count = -2` ce qui est impossible.

Donc `backslash_count` doit valoir 4 et `path_length` doit valoir 45.

Ainsi, le chemin `C:\Users\username\mySpecialFolder\Univers.exe` convient car :
- il y a bien 4 backslashs
- la longueur du chemin est 45

Ainsi, si on exécute le programme, celui-ci renvoie désormais `You are lost !`.

Comme on peut le voir dans le pseudo-code, on sait que le résultat attendu est 42.

## Somme de trois cubes valant 42

On a terminé l'analyse du programme.  
Il nous faut désormais trouver une solution à l'équation : `value1 ^ 3 + value3 ^ 3 + value5 ^ 3 = 42`

Pas la peine d'essayer de résoudre soi-même l'équation.  
Pendant longtemps, personne n'a jamais trouvé de solution.

Ce n'est qu'en 2019 que des chercheurs sont parvenus à trouver la solution, la voici :  
`42 = (-80538738812075974)^3 + 80435758145817515^3 + 12602123297335631^3`

Comme je l'ai expliqué au tout début, il est essentiel d'utiliser un type BigInteger pour résoudre ce genre d'équation car les valeurs solutions ne peuvent être codées sur 64 bits.

Le flag du challenge est donc :
`Univers.exe -80538738812075974 0 80435758145817515 0 12602123297335631`
