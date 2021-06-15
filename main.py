import struct
import random
import matplotlib.pyplot as plt


class MD4:
    """An implementation of the MD4 hash algorithm."""

    width = 32
    mask = 0xFFFFFFFF

    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]  # A, B, C, D

    def __init__(self, msg=None):
        self.msg = msg

        # Pre-processing: Total length is a multiple of 512 bits.
        ml = len(msg) * 8  # кол-во бит
        msg += b"\x80"
        msg += b"\x00" * (-(len(msg) + 8) % 64)
        msg += struct.pack("<Q", ml)  # превод в little-endian

        # Process the message in successive 512-bit chunks.
        self._process([msg[i: i + 64] for i in range(0, len(msg), 64)])

    def bytes(self):
        """:return: The final hash value as a `bytes` object."""
        return struct.pack("<4L", *self.h)

    def hexdigest(self):
        """:return: The final hash value as a hexstring."""
        return "".join(f"{value:02x}" for value in self.bytes())

    def _process(self, chunks):
        for chunk in chunks:
            X, h = list(struct.unpack("<16I", chunk)), self.h.copy()  # 16 слов I - 4 байта

            # Round 1.
            Xi = [3, 7, 11, 19]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n, Xi[n % 4]
                hn = h[i] + MD4.F(h[j], h[k], h[l]) + X[K]
                h[i] = MD4.lrot(hn & MD4.mask, S)

            # Round 2.
            Xi = [3, 5, 9, 13]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n % 4 * 4 + n // 4, Xi[n % 4]
                hn = h[i] + MD4.G(h[j], h[k], h[l]) + X[K] + 0x5A827999
                h[i] = MD4.lrot(hn & MD4.mask, S)

            # Round 3.
            Xi = [3, 9, 11, 15]
            Ki = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = Ki[n], Xi[n % 4]
                hn = h[i] + MD4.H(h[j], h[k], h[l]) + X[K] + 0x6ED9EBA1
                h[i] = MD4.lrot(hn & MD4.mask, S)

            self.h = [((v + n) & MD4.mask) for v, n in zip(self.h, h)]

    @staticmethod
    def F(x, y, z):
        return (x & y) | (~x & z)

    @staticmethod
    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    @staticmethod
    def H(x, y, z):
        return x ^ y ^ z

    @staticmethod
    def lrot(value, n):
        lbits, rbits = (value << n) & MD4.mask, value >> (MD4.width - n)
        return lbits | rbits


def generate_random_string(length) -> str:
    letters = 'abcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()_+={}[]:"<>?/'

    rand_string = ''.join(random.choice(letters) for i in range(length))
    return rand_string


def collision_of_2_random():
    #  Exercise #3
    print('Da finding of collision')

    print()
    print('Введите длинну генерируемой последовательности: ')
    length = int(input())

    print("Введите параметр К (<32):")
    k_max = int(input())

    words = []
    hashes = []
    part_hashes = []
    results = []

    word = generate_random_string(length)
    hash = MD4(word.encode()).hexdigest()

    count_massive = []

    for k in range(1, k_max + 1):
        count = 0
        while hash[:k] not in part_hashes:
            part_hashes.append(hash[:k])
            words.append(word)
            hashes.append(hash)

            word = generate_random_string(length)
            hash = MD4(word.encode()).hexdigest()
            count += 1
        results.append(part_hashes.index(hash[:k]))
        count_massive.append(count)
        print("Бит: ", 4*k, "Кол-во сочетаний: ", count)
        print()

    plt.title("График зависимости времени разложения N от k")  # заголовок
    plt.xlabel("k-бит")  # ось абсцисс
    plt.ylabel("N-количество комбинаций")  # ось ординат
    plt.grid()  # включение отображение сетки
    plt.plot([x*4 for x in range(1, k_max + 1)], count_massive)
    plt.show()

    print('Collision detected on:', sum(count_massive))
    print('Collision detected for words:', words[results[len(results)-1]], word)
    print('Collision detected for hashes:', hashes[results[len(results)-1]], hash)
    print()


def collision_of_pswd():
    #  Exercise #4
    print('Da finding of collision by brute force')

    print()
    print('Введите длинну генерируемой последовательности: ')
    length = int(input())

    print("Введите параметр К (<32):")
    k_max = int(input())

    pswd = 'password'
    hash_pswd = MD4(pswd.encode()).hexdigest()

    print('hash of password: ', hash_pswd)

    words = []
    hashes = []
    part_hashes = []
    results = []
    count_massive = []

    for k in range(1, k_max + 1):
        count = 0
        while hash_pswd[:k] not in part_hashes:
            word = generate_random_string(length)
            hash = MD4(word.encode()).hexdigest()

            part_hashes.append(hash[:k])
            words.append(word)
            hashes.append(hash)

            count += 1
        results.append(part_hashes.index(hash[:k]))
        count_massive.append(count)
        print("Бит: ", 4*k, "Кол-во сочетаний: ", count)
        print()

    plt.title("График зависимости времени разложения N от k")  # заголовок
    plt.xlabel("k-бит")  # ось абсцисс
    plt.ylabel("N-количество комбинаций")  # ось ординат
    plt.grid()  # включение отображение сетки
    plt.plot([x*4 for x in range(1, k_max + 1)], count_massive)
    plt.show()

    print('Collision detected on:', sum(count_massive))
    print('Collision detected for words:', words[results[len(results)-1]], word)
    print('Collision detected for hashes:', hashes[results[len(results)-1]], hash)
    print()


def main():
    print("Testing the MD4 class.")
    print()

    print("Enter message: ")
    input_message = input()

    messages = ["", "abc", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"]

    known_hashes = [
        "31d6cfe0d16ae931b73c59d7e0c089c0",
        "a448017aaf21d8525fc10ae87aa6729d",
        "043f8582f241db351ce627e153e7f0e4",
    ]

    print("Message: ", input_message)
    print("Hash:  ", MD4(input_message.encode()).hexdigest())
    print()

    print('Avalanche effect:')
    print()
    print("Message: 122")
    print("Message bin: ", ''.join('{0:08b}'.format(ord(x), 'b') for x in '122'))
    print("Hash:  ", MD4(b'122').hexdigest())
    print()

    print("Message: 123")
    print("Message bin: ", ''.join('{0:08b}'.format(ord(x), 'b') for x in '123'))
    print("Hash:  ", MD4(b'123').hexdigest())
    print()

    mes1 = "{0:0128b}".format(int(MD4(b'122').hexdigest(), 16))
    mes2 = "{0:0128b}".format(int(MD4(b'123').hexdigest(), 16))

    print(hex(int(mes1, 2)))
    print(hex(int(mes2, 2)))

    print("Comparing hashes:")
    print("122: ", mes1)
    print("123: ", mes2)

    counter = 0
    count = sum([counter + 1 for i, j in zip(mes1, mes2) if i == j])

    print(f'Число совпадений в хешах в бинарном виде {count} при длине {len(mes2)}')
    print()

    for message, expected in zip(messages, known_hashes):
        print("Message: ", message)
        print("Expected:", expected)
        print("Actual:  ", MD4(message.encode()).hexdigest())
        print()

    collision_of_2_random()
    collision_of_pswd()


if __name__ == "__main__":
    main()
