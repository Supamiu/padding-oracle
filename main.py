# i le bloc et j la position
# P28 = D28 ^ C18
# Le vecteur d'initialisation est 0x0000000000000000
import base64
import time
import requests

import curses

# Soit C -> chiffré

C = bytearray.fromhex(
    "0eb32a58142e7af30b73ddada9412ed12ff7b13c8df1916ec18c9595f561a2ea486bb1d91033d3bf63c501972cf8d09440b1b9b2210d02cc429c537a70418de1a1e2e6d26ea5ed4f1c9c1d30790a7ac09c2a3367548dfcd146d825c052b108fdd0a672fe4b89a5084a4eab61fdb12f8e47b79b12b1acc9482447d303dd57acb9b68bff1ca6ab41f13bfeb4a430455195d3f81b85601d96abb3cc7f4ee1debb914a1764877ab4b4f7dfd5e108a0bba818d076ee75b40485e9cee8a0e9579803ba02843521ea3de680391d406913741ec329c1506c7cb94c54a1d79e7fa505b8af0750e688e03820c326e8aa51157c021722f7e22f8d733f24dece8e4d21b876ecb18773842c635b1ea78361e193133b955169c80ee3a57f1d6d49a939ee9f93ba2b1a137cbc5aa63e68f284cf530ed55556e747305327d51ae682ed06720cdb49c1d3df741fc8aa774bab6defcfbf30ff5e47de0a61b1e6d0b85ee9907942e66a9d5fc2aea99cfe0782d3d766a630c4809767d237c0d583271f4ea1d11a7574da3b025c03cb671441e2d50cbff89923622d74224acf59b8fe09f0edc24b1735253242bd44b982309f7ab7d153e19506a02f5e5387e4523dbd200ef1e7c9ef01c72d0f3271201d8fe69863173b2f009ebd2b16e08f55830f21d99ff6877b001305a6d0fab3150ef10eba12d1e00bae1b99f3e702dd9c04c5c47e6ce6c196886e52e7d5cb8f8921568c32eac7967406ab48")


def main():
    # X est le block qu'on manipule
    X = bytearray.fromhex("0000000000000000")

    # P -> Plaintext
    P = bytearray()

    # On stock le block précédent pour XOR avec le résultat, le premier étant IV, un tableau de 0
    previous_block = bytearray.fromhex("0000000000000000")

    # On veut pouvoir monitorer le nombre de requêtes envoyées
    total_requests = 0
    # Pour chaque bloc de notre chaine cipher
    for block_index in range(0, int(len(C) / 8) + 1):
        # Pour chaque octet dans le bloc en cours
        for octet_index in reversed(range(0, 8)):
            # On va essayer toutes les valeurs possibles entre 0 et 255 pour notre octet
            for octet_value in range(0, 256):
                # On set la valeur qu'on veut tester sur notre octet
                X[octet_index] = octet_value
                # Puis on fait le call vers le serveur pour savoir si le padding est valide
                found = test(X, C[block_index * 8:block_index * 8 + 8])
                # Via curses on monitor le status du script
                seconds = int(time.time() - start_time)
                m, s = divmod(seconds, 60)
                h, m = divmod(m, 60)
                stdscr.addstr(0, 0, "%d:%02d:%02d" % (h, m, s))
                stdscr.addstr(1, 0, str(total_requests) + " requests sent\n")
                stdscr.addstr(2, 0, str(int((len(P) / len(C)) * 100)) + "% decrypted\n")
                stdscr.addstr(3, 0, str(int((1.0 - ((octet_index + 1) / 8)) * 100)) + "% of current block done\n")
                stdscr.addstr(4, 0, P.decode("utf-8"))
                stdscr.refresh()
                total_requests += 1
                # Si le serveur a confirmé le padding
                if found:
                    # Si on n'est pas sur le premier octet du bloc, on doit mettre à jour le padding (si on est à 0,
                    # le padding ne doit pas passer à 9 mais bien rester à 8
                    if octet_index > 0:
                        update_padding(X, octet_index)
                    # Une fois le padding mis à jour, on peut arrêter de chercher une valeur pour l'octet,
                    # on casse donc la boucle
                    break
        # On décrypte le bloc à partir du block qui fourni un padding à 8 valide
        decrypted = x_to_p(xor_arrays(X, previous_block))
        # Puis on l'ajoute à notre plaintext P
        P = concat_arrays(P, decrypted)
        # On met à jour le bloc précédent pour le prochiane itération de la boucle
        previous_block = C[block_index * 8:block_index * 8 + 8]
        # On reset le bloc qu'on manipule, histoire d'avoir une meilleur lisibilité pour le debug
        X = bytearray.fromhex("0000000000000000")
    return 0


# Met à jour le padding pour un index donné
def update_padding(x, last_index):
    for index in range(last_index, 8):
        x[index] = x[index] ^ 8 - last_index ^ (9 - last_index)


# Permet de tester un bloc custom avec un bloc de notre cipher auprès du serveur
def test(my_bloc, bloc, tries=0):
    # On concatène les tableaux
    data = concat_arrays(my_bloc, bloc)
    # On s'assure que la taille est conforme
    assert len(data) == 16
    try:
        res = requests.post("http://padding-oracle.cleverapps.io/",
                            base64.b64encode(data).decode('ascii'))
    # Il arrive que le serveur ai une erreur de connexion, on retry dans ce cas avec une limite de 10 tentatives.
    except requests.exceptions.ConnectionError as error:
        if tries < 10:
            time.sleep(1)
            return test(my_bloc, bloc, tries + 1)
        else:
            raise error
    # On retourne un booléen en comparant le résultat à celui attendu
    return res.text == "1"


# Permet de récupérer une chaine Plaintext pré-XOR (il faut XOR le bloc N-1 ou le vecteur d'initialisation après)
# à partir d'un tableau qui contient un padding de 8 valide.
def x_to_p(x):
    return xor_arrays(x, bytearray.fromhex("0808080808080808"))


# Simple helper pour XOR deux bytearrays de taille égale.
def xor_arrays(array1, array2):
    result = bytearray()
    for i in range(0, 8):
        result.append(array1[i] ^ array2[i])
    return result


# Simple helper pour concaténer deux bytearrays.
def concat_arrays(a, b):
    c = bytearray()
    c[:] = a
    for data in b:
        c.append(data)
    return c


# Le launcher, initialise curses et le débranche à la fin de l'exécution,
# en précisant combien de temps l'opération a pris.
if __name__ == "__main__":
    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()
    start_time = time.time()
    main()
    curses.echo()
    curses.nocbreak()
    curses.endwin()
    print()
