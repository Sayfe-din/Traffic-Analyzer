Nous avons a disposition des structure permettant une meilleur gestion des trames lues au cours du programme et chacune des entetes seront porter par une structure appelée CellFrame qui contiens toute les entete d'une trame lue (du moins ce que le code a pu indentifier)

Les fonctions extract permettent d'a partir d'un flux de fichier passer en parametre (FILE *f) avec la ligne courante (char **line) d'extraire les données correspondantes a l'entete.

Il se peut que parfois un probleme d'alignement se produisent dû a la presence d'options dans l'entete precedente. Pour y remedier nous utilisons une variable offset qui traduit l'offset relatif au debut de la ligne et non au debut de la trace nous permettant de savoir quand charger une ligne lorsque nous arrivons a la fin de la ligne (offset==16) evitant ainsi des lectures d'eventuelles caracteres invoulue a la suite de la ligne.

Des fonctions d'affichage permettent un affichage dans un fichier (fprint_XXX) pour visualisé le trafic de la trace passée en parametre, ou dans la sortie standard (print_XXX) pour afficher toute les informations analysées. Des fonctions de liberations de mémoire sont presents pour permettre des liberations plus lisible et bien plus pratique comme free_CellFrame().

flush_data() permet de mettre a jour le Checksum de TCP pour pouvoir verifier l'integrité du segment mais aussi pour pouvoir lire la trame suivante

Un systeme de filtrage facilement implementable grace au systeme de liste chainée de trame (en supprimant les noeuds ne remplissant pas le conditions et en rattachant ceuux qui les remplissent)
