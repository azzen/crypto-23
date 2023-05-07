
# IMPORTANT
# IL EST PRIMORDIAL DE NE PAS CHANGER LA SIGNATURE DES FONCTIONS
# SINON LES CORRECTIONS RISQUENT DE NE PAS FONCTIONNER CORRECTEMENT

from unidecode import unidecode
from statistics import mean

ASCII_SHIFT = ord('A') # will be used to skip the first 65 entries in the ASCII table
MAX_KEY_LENGTH = 20

def sanitize(text):
    """
    Parameters
    ----------
    text: the text to clean

    Returns
    -------
    the text sanitized: whitespaces and special characters removed or replaced, only alphabetic 
    characters and upper case only
    """
    return "".join(c for c in unidecode(text, "utf-8").upper() if c.isalpha())

def chi_square(freq, shift, ref_freq):
    """
    Parameters
    ----------
    freq: arrays of observations
    shift: shift to apply to the index of the observations array
    ref_freq: arrays of expected values

    Returns
    -------
    The chi^2 test value computed between the freq and ref_freq arrays
    """ 
    chi2 = 0
    for i, expected in enumerate(ref_freq):
        chi2 += ((freq[((i + shift) % 26)] + expected)**2) / expected
    return chi2

def partition(text, part_length):
    """
    Parameters
    ----------
    text: the text to partition
    key_len: length of each parts    
    Returns
    -------
    The text divided in chunks of length key_len 
    """ 
    chunks = []
    text_len = len(text)
    if part_length == 0:
        chunks.append(text)
        return chunks
    for i in range(0, text_len, part_length):
        chunks.append(text[i:i + part_length])
    return chunks

def column_partition(text, column_len):
    """
    Parameters
    ----------
    text: the text to partition in columns
    column_len: the length of the column
    Returns
    -------
    The text divided in chunks such that each chunk is composed of letters at 
    positions 0 + i, l + i, 2l + i, etc. for 0 <= i <= l
    Example with ABCDEF and l = 2
    AB
    CD
    EF
    partition = [ACE, BDF]
    """
    chunks = [""] * column_len
    text_len = len(text)
    for j in range(column_len):
        for i in range(j, text_len, column_len):
            chunks[j] += text[i]
    return chunks

def vigenere_caesar_keys_sequence(chunks_count, vigenere_key, caesar_key):
    """
    Parameters
    ----------
    chunks_count: how many successive caesar_encrypt should be computed with vigenere_key
    vigenere_key: the starting Vigenere key
    caesar_key: the Caesar key used for each successive caesar_encrypt
    Returns
    -------
    A list of <chunks_count> successively applied caesar_encrypt to the <vigenere_key> with <caesar_key>
    """
    keys = [vigenere_key]
    for i in range(chunks_count):
        keys.append(caesar_encrypt(keys[i], caesar_key))
    return keys

def caesar_encrypt(text, key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    key: the shift which is a number

    Returns
    -------
    the ciphertext of <text> encrypted with Caesar under key <key>
    """
    text = sanitize(text)
    return "".join(chr((((ord(c)) + key - ASCII_SHIFT) % 26) + ASCII_SHIFT) for c in text)


def caesar_decrypt(text, key):
    """
    Parameters
    ----------
    text: the ciphertext to decrypt
    key: the shift which is a number

    Returns
    -------
    the plaintext of <text> decrypted with Caesar under key <key>
    """
    text = sanitize(text)
    return "".join(chr((((ord(c)) - key - ASCII_SHIFT) % 26) + ASCII_SHIFT) for c in text)


def freq_analysis(text):
    """
    Parameters
    ----------
    text: the text to analyse

    Returns
    -------
    list
        the frequencies of every letter (a-z) in the text.

    """
    # Each value in the vector should be in the range [0, 1]
    freq_vector = [0] * 26
    text = sanitize(text)
    text_len = len(text)
    for i in range(len(freq_vector)):
        freq_vector[i] = text.count(chr(i + ASCII_SHIFT)) / text_len
    return freq_vector


def caesar_break(text, ref_freq):
    """
    Parameters
    ----------
    text: the ciphertext to break
    ref_freq: the output of the freq_analysis function on a reference text

    Returns
    -------
    a number corresponding to the caesar key
    """
    text = sanitize(text)
    min_chi_square = 10000
    min_chi_square_key = 0
    freq = freq_analysis(text)
    for k in range(26):
        cs = chi_square(freq, k, ref_freq)
        if cs < min_chi_square:
            min_chi_square = cs
            min_chi_square_key = k
    return min_chi_square_key


def vigenere_encrypt(text, key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    key: the keyword used in Vigenere (e.g. "pass")

    Returns
    -------
    the ciphertext of <text> encrypted with Vigenere under key <key>
    """
    text = sanitize(text)
    key = sanitize(key)
    pos = 0
    result = ""
    if len(key) == 0: return text
    for c in text:
        shift = ord(key[pos]) - ASCII_SHIFT
        result += chr(((ord(c) + shift - ASCII_SHIFT) % 26) + ASCII_SHIFT)
        pos = (pos + 1) % len(key)
    return result


def vigenere_decrypt(text, key):
    """
    Parameters
    ----------
    text: the ciphertext to decrypt
    key: the keyword used in Vigenere (e.g. "pass")

    Returns
    -------
    the plaintext of <text> decrypted with Vigenere under key <key>
    """
    text = sanitize(text)
    key = sanitize(key)
    pos = 0
    result = ""
    if len(key) == 0: return text
    for c in text:
        shift = ord(key[pos]) - ASCII_SHIFT
        result += chr(((ord(c) - shift - ASCII_SHIFT) % 26) + ASCII_SHIFT)
        pos = (pos + 1) % len(key)
    return result


def coincidence_index(text):
    """
    Parameters
    ----------
    text: the text to analyse

    Returns
    -------
    the index of coincidence of the text
    """
    text = sanitize(text)
    s = 0
    l = len(text)
    if l == 1: return 0
    for i in range(26):
        occurrences = text.count(chr(i + ASCII_SHIFT))
        s += occurrences * (occurrences - 1)
    return (26 * s) / (l * (l - 1))


def vigenere_break(text, ref_freq, ref_ci):
    """
    Parameters
    ----------
    text: the ciphertext to break
    ref_freq: the output of the freq_analysis function on a reference text
    ref_ci: the output of the coincidence_index function on a reference text

    Returns
    -------
    the keyword corresponding to the encryption key used to obtain the ciphertext
    """
    text = sanitize(text)
    best_candidate = {'ci': 0, 'chunks': ''}
    for l  in range(1, MAX_KEY_LENGTH + 1):
        chunks = column_partition(text, l)
        ci = mean(coincidence_index(c) for c in chunks)
        if abs(ci - ref_ci) < abs(best_candidate['ci'] - ref_ci):
            best_candidate['ci'] = ci
            best_candidate['chunks'] = chunks
    return "".join(chr(i + ASCII_SHIFT) for i in [caesar_break(p, ref_freq) for p in best_candidate['chunks']])

def vigenere_caesar_encrypt(text, vigenere_key, caesar_key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    vigenere_key: the keyword used in Vigenere (e.g. "pass")
    caesar_key: a number corresponding to the shift used to modify the vigenere key after each use.

    Returns
    -------
    the ciphertext of <text> encrypted with improved Vigenere under keys <key_vigenere> and <key_caesar>
    """
    text = sanitize(text)
    vigenere_key = sanitize(vigenere_key)
    chunks = partition(text, len(vigenere_key))
    keys = vigenere_caesar_keys_sequence(len(chunks), vigenere_key, caesar_key)
    result = ""
    for i, chunks in enumerate(chunks):
        result += vigenere_encrypt(chunks, keys[i]) 
    return result

def vigenere_caesar_decrypt(text, vigenere_key, caesar_key):
    """
    Parameters
    ----------
    text: the plaintext to decrypt
    vigenere_key: the keyword used in Vigenere (e.g. "pass")
    caesar_key: a number corresponding to the shift used to modify the vigenere key after each use.

    Returns
    -------
    the plaintext of <text> decrypted with improved Vigenere under keys <key_vigenere> and <key_caesar>
    """
    text = sanitize(text)
    vigenere_key = sanitize(vigenere_key)
    chunks = partition(text, len(vigenere_key))
    keys = vigenere_caesar_keys_sequence(len(chunks), vigenere_key, caesar_key)
    result = ""
    for i, chunks in reversed(list(enumerate(chunks))):
        result = vigenere_decrypt(chunks, keys[i]) + result
    return result

def vigenere_caesar_break(text, ref_freq, ref_ci):
    """
    Parameters
    ----------
    text: the ciphertext to break
    ref_freq: the output of the freq_analysis function on a reference text
    ref_ci: the output of the coincidence_index function on a reference text

    Returns
    -------
    pair
        the keyword corresponding to the vigenere key used to obtain the ciphertext
        the number corresponding to the caesar key used to obtain the ciphertext
    """
    text = sanitize(text)
    best_candidate = { 'chunks': "", 'ci': 1000, 'caesar_key': 0, 'key_length': 0 }
    for l in range(1, MAX_KEY_LENGTH + 1):
        text_parts = partition(text, l)
        for ck in range(26):
            vigenere_only = "".join([caesar_decrypt(c, (ck * i) % 26) for i, c in enumerate(text_parts)])
            chunks = column_partition(vigenere_only, l)
            ci = mean(coincidence_index(c) for c in chunks)
            if abs(ci - ref_ci) < abs(best_candidate['ci'] - ref_ci):
                best_candidate['chunks'] = chunks
                best_candidate['ci'] = ci
                best_candidate['caesar_key'] = ck
                best_candidate['key_length'] = l
    vigenere_key = "".join(chr(i + ASCII_SHIFT) for i in [caesar_break(p, ref_freq) for p in best_candidate['chunks']])
    return (vigenere_key, best_candidate['caesar_key'])

def main():
    print("Welcome to the Vigenere breaking tool")

    #
    # Retrieving reference values
    #

    ref = open("reference.txt", "r")
    ref_text = ref.read()
    ref_ci = coincidence_index(ref_text)
    ref_freq = freq_analysis(ref_text)

    #
    # Vigenere break
    #    

    print("+" + "-" * 50 + "+")
    print("| Vigenere Break" + " " * (52 - len("| Vigenere Break ")) + "|")
    print("+" + "-" * 50 + "+")

    f = open('vigenere.txt')
    ct = f.read()
    vk = vigenere_break(ct, ref_freq, ref_ci)

    print(f"\x1b[32m[+] Key found: (vigenere: \x1b[1m{vk}\x1b[0m\x1b[32m)\x1b[0m")
    print("\x1b[32m[+] Plaintext:\x1b[0m")
    print(vigenere_decrypt(ct, vk))
    f.close()

    #
    # Better vigenere break
    #

    print("+" + "-" * 50 + "+")
    print("| VigenereCaesar Break" + " " * (52 - len("| VigenereCaesar Break ")) + "|")
    print("+" + "-" * 50 + "+")

    f = open("vigenereAmeliore.txt")
    ct = f.read()
    vk, ck = vigenere_caesar_break(ct, ref_freq, ref_ci)

    print(f"\x1b[32m[+] Keys found: (vigenere: \x1b[1m{vk}\x1b[0m\x1b[32m, caesar: \x1b[1m{ck}\x1b[0m\x1b[32m)\x1b[0m")
    print("\x1b[32m[+] Plaintext:\x1b[0m")
    print(vigenere_caesar_decrypt(ct, vk, ck))
    f.close()
    
if __name__ == "__main__":
    main()


