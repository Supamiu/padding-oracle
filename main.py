# i le bloc et j la position
# P28 = D28 ^ C18
# Le vecteur d'initialisation est 0x0000000000000000
import base64

import requests
# Soit C -> chiffré
C = bytearray.fromhex(
    "0eb32a58142e7af30b73ddada9412ed12ff7b13c8df1916ec18c9595f561a2ea486bb1d91033d3bf63c501972cf8d09440b1b9b2210d02cc429c537a70418de1a1e2e6d26ea5ed4f1c9c1d30790a7ac09c2a3367548dfcd146d825c052b108fdd0a672fe4b89a5084a4eab61fdb12f8e47b79b12b1acc9482447d303dd57acb9b68bff1ca6ab41f13bfeb4a430455195d3f81b85601d96abb3cc7f4ee1debb914a1764877ab4b4f7dfd5e108a0bba818d076ee75b40485e9cee8a0e9579803ba02843521ea3de680391d406913741ec329c1506c7cb94c54a1d79e7fa505b8af0750e688e03820c326e8aa51157c021722f7e22f8d733f24dece8e4d21b876ecb18773842c635b1ea78361e193133b955169c80ee3a57f1d6d49a939ee9f93ba2b1a137cbc5aa63e68f284cf530ed55556e747305327d51ae682ed06720cdb49c1d3df741fc8aa774bab6defcfbf30ff5e47de0a61b1e6d0b85ee9907942e66a9d5fc2aea99cfe0782d3d766a630c4809767d237c0d583271f4ea1d11a7574da3b025c03cb671441e2d50cbff89923622d74224acf59b8fe09f0edc24b1735253242bd44b982309f7ab7d153e19506a02f5e5387e4523dbd200ef1e7c9ef01c72d0f3271201d8fe69863173b2f009ebd2b16e08f55830f21d99ff6877b001305a6d0fab3150ef10eba12d1e00bae1b99f3e702dd9c04c5c47e6ce6c196886e52e7d5cb8f8921568c32eac7967406ab48")

# X est le block qu'on manipule
X = bytearray.fromhex("0000000000000000")

# P -> Plaintext
P = bytearray()

# D -> Déchiffré
D = bytearray()


def main():
    for octet_index in reversed(range(0, 8)):
        for octet_value in range(0, 256):
            X[octet_index] = octet_value
            found = test(X, C[:8])
            if found:
                print("found first one : " + print_block(X))
                break
    return 0


def print_block(block):
    return ''.join('{:02x}'.format(x) for x in block)


def test(my_bloc, bloc):
    data = concat_arrays(my_bloc, bloc)
    print_block(data)
    assert len(data) == 16
    res = requests.post("http://padding-oracle.cleverapps.io/",
                        base64.b64encode(data).decode('ascii'))
    return res.text == "1"


def concat_arrays(a, b):
    c = bytearray()
    c[:] = a
    for data in b:
        c.append(data)
    return c


if __name__ == "__main__":
    main()
