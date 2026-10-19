"""Experimental utility library for cryptography"""
from typing_extensions import LiteralString, Tuple, Dict, List
from itertools import chain
import numpy as np
import string
import time
import math
import random
import collections
import re



######################################
# utilities progrom for cryptography #
######################################

class ReverseCipher:
    @staticmethod
    def reverse_cipher(text:str)->str:
        """Get the the text reverse
        :param text: Text to reverse
        :return: reverse text"""
        return text[::-1]

    #NOTE: When recognized (scheme/model), it is easy to decrypt !
    @staticmethod
    def atbash_cipher(text:str)->str:
        """The text will be rewrite using Aphabetical reversal (so A become Z (So Z is in A position), B->Y...)
        :param: plain text
        :return: atbash cipher"""
        cipher = []
        initial_shift = 25
        for letter in text:
            if letter.isalpha():
                alpha_start_position = ord("a") if ord(letter)>=97 else ord("A")
                # add the new position of this letter based on our new alphabet
                letter_position = ord(letter)
                shift_diff = letter_position - alpha_start_position # either 0 or higher
                shift = initial_shift - shift_diff
                cipher.append(chr(alpha_start_position + shift))
            else:
                cipher.append(letter)

        return "".join(cipher)

class CaesarCipherModel:
    @staticmethod
    def brute_force_decrypt_caesar_cipher(cipher:str):
        """We do not have any key of cipher, but we suppose it is a caesar cipher.
        This code will iterate over the cipher message by texting any possible key and try to decrypt
        the message. For each iteration, the elapsed time will be recorded."""
        # we create our model
        string_model = string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation
        t0 = time.perf_counter()
        tn= time.perf_counter()
        t_previous = 0
        print(f"Total Elapsed time: {tn-t0}")
        for shift_value in range(len(string_model)):
            text = ""
            for char in cipher:
                if char.isascii():
                    # find char in our string model
                    index_char = string_model.find(char)
                    if index_char == -1: # character not defined in our string model
                        text = text + char
                    else:
                        shift_back = (index_char -shift_value)
                        if shift_back <0:
                            shift_back = shift_back + len(string_model)
                        text = text + string_model[shift_back]
                else:
                    text = text + char
            print(f"Key value: {shift_value} - {text}")
            tn=time.perf_counter()
            print(f"Total Elapsed time: {tn-t0}")
            print(f"Elapsed time between iteration: {(tn-t0) - t_previous}")
            t_previous = tn-t0 # update t_previous
    #NOTE: All of this algortihm are easy to decrypt by brute force, as there is only 25 possibilities key for ceasar for example.
    # And depending on the language as english it is easy to recognize the algorithm as in english some letter as E and T will have
    # a high frequency occurrence.
    #NOTE 2: this ceasar algorithm work only with letter !
    @staticmethod
    def ceasar_cipher_alpha(text:str, shift_key:int=3, is_encrypted:bool=True)->str:
        """Ceasar algorithm to encrypt a text he will shift the alphabet letter of shift_key position, 
        so for ceasar it key was 3 shift (so A positon 0 become D (position 3))
        .param text: plain text
        :param shift_key: shifting number
        :param is_encrypted: Weither the text need to be encrypted (True) or decrypted (False)
        :raises ValueError: Error raised if shift_key not in the range of 0-25 (inclusive)
        :return: ceasar cipher"""
        if not (shift_key>= 0 and shift_key<= 25):
            raise ValueError("Shift_key: must be between 0-25")
        cipher = []

        if is_encrypted:
            for letter in text:
                if letter.isalpha():
                    alpha_start_position = ord("a") if ord(letter)>=97 else ord("A")
                    # add the new position of this letter based on our new alphabet
                    letter_position = ord(letter)
                    # 26 instead of 25 as A start at 0 (position 97 or 65) then we move to z with 25 shift
                    # by doing so we normalize the shifting of letter so that we stay in the range [97/65:97/6+25]
                    cipher.append(chr((letter_position - alpha_start_position + shift_key )%26 + alpha_start_position)) # E(x) = (x + k) mod 26
                else:
                    cipher.append(letter)
        else:
            
            for letter in text:
                if letter.isalpha():
                    alpha_start_position = ord("a") if ord(letter)>=97 else ord("A")
                    # add the new position of this letter based on our new alphabet
                    letter_position = ord(letter)
                    # 26 instead of 25 as A start at 0 (position 97 or 65) then we move to z with 25 shift
                    # by doing so we normalize the shifting of letter so that we stay in the range [97/65:97/6+25]
                    cipher.append(chr((letter_position - alpha_start_position - shift_key )%26 + alpha_start_position)) #E(x) = (x - k) mod 26
                else:
                    cipher.append(letter)

        return "".join(cipher)

    #NOTE: we could apply after the ceasar_cipher for letter a ceasar for number then a ceasar cipher for ponctuation it would mean 3 different function
    # or fuse those 3 three to one fucntion by setting our model, it may the ceasar more robust than doing 3 of them separatly.
    # or model will be somethig as: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789 !?.'" so the shifting is applyied on 66 positions
    @staticmethod
    def ceasar_cipher_string(text:str, shift_key:int=3, is_encrypted:bool=True, model:str="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789 !?.\'")->str:
        """Ceasar algorithm to encrypt a text he will shift the alphabet letter of shift_key position, 
        so for ceasar it key was 3 shift (so A positon 0 become D (position 3))
        .param text: plain text
        :param shift_key: shifting number
        :param is_encrypted: Weither the text need to be encrypted (True) or decrypted (False)
        :param model: Model use to encrypt our string message. 
        :raises ValueError: Error raised if shift_key not in the range of 0-len(model) (inclusive)
        :return: ceasar cipher"""
        if not (shift_key>= 0 and shift_key<= len(model)):
            raise ValueError("Shift_key: must be between 0-len(model)")
        cipher = []
        for char in text:
            if char in model:
                # get letter position in model
                char_position = model.find(char)
                if is_encrypted:
                    # get the new position value
                    char_next_position = char_position + shift_key
                else:
                    char_next_position = char_position - shift_key
                # make sure to be in the range of our model
                if char_next_position >= len(model): # out of range cases (>= and not > because A is position 0 and not 1 so index start at 0)
                    char_next_position = char_next_position - len(model)
                elif char_next_position < 0:
                    char_next_position = char_next_position + len(model)
                else:
                    pass
                cipher.append(model[char_next_position])
            else:
                cipher.append(char)

        return "".join(cipher)

    #NOTE: method to avoid because if teh shift number is higher than the length number a error will be raised
    #NOTE 2: Not really the same as the implemented caesar on top (original), because after Z come ABC and not anymore abc due to the direct shift
    # operate directly on the model with separate low model instead of having just one
    @staticmethod
    def caesar_cipher_string_v2(text:str, shift_key:int=3, is_encrypted:bool=True, models:list=["ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz","123456789"])->Tuple[str, LiteralString, LiteralString, Dict[int,int]]:
        """Ceasar algorithm to encrypt a text he will shift the alphabet letter of shift_key position, 
        so for ceasar it key was 3 shift (so A positon 0 become D (position 3)).

        :param text: plain text
        :param shift_key: shifting number
        :param is_encrypted: Weither the text need to be encrypted (True) or decrypted (False)
        :param models: Model use to encrypt our string message.
        :raise KeyError: Error raised when shifting key value is higher than the lower model size
        :return: ceasar cipher"""

        model_before_shifting = "".join(models)
        try:
            model_after_shifting_list = [models[i][shift_key:]+models[i][:shift_key] for i in range(len(models))]
        except Exception as e:
            raise KeyError("Shifting key value is higher than the lower model size!")
        model_after_shifting = "".join(model_after_shifting_list)
        # create the translation table model: mapping
        translation_table = str.maketrans(model_before_shifting, model_after_shifting)
        caesar_cipher = text.translate(translation_table)
        return caesar_cipher, model_before_shifting, model_after_shifting, translation_table


    def __init__(self, shift: int=3)->None:
        self.shift = shift % 26
        self.encrypt_dict = {}
        self.decrypt_dict = {}
        self._build_dictionaries()

    def _build_dictionaries(self)->None:
        """Builds lookup tables for uppercase and lowercase letters."""
        for alphabet in (string.ascii_lowercase, string.ascii_uppercase):
            # Shift alphabet using slicing: [shift:] + [:shift]
            shifted_alphabet = alphabet[self.shift:] + alphabet[:self.shift]
            
            # Map original -> shifted
            for p_char, c_char in zip(alphabet, shifted_alphabet):
                self.encrypt_dict[p_char] = c_char
                self.decrypt_dict[c_char] = p_char  # Reverse mapping for decryption

    def encrypt(self, text: str) -> str:
        """Transforms text using encrypt_dict lookup."""
        return "".join(self.encrypt_dict.get(char, char) for char in text)

    def decrypt(self, text: str) -> str:
        """Transforms text using decrypt_dict lookup."""
        return "".join(self.decrypt_dict.get(char, char) for char in text)

#NOTE: Compare to substitution cipher as caesar cipher, in transposition cipher the character is not change/remove it just change of position in the string
# the string will have exactly the same number and same characters but in a different position.
# the strength of such cipher is seen more when the message is big. For long message transposition cipher is more robust than caesar cipher, and letter
# frequency a bit stronger than caesar cipher. So Brut force is more difficult on transposition cipher more the message is long. And will depend on
# the type of transposition cipher used... there are 3 categories of transposition cipher: Fence Rail Cipher (Zig Zag cipher), columns Cipher, route Cipher.
# Zig Zag cipher is a special case of route cipher.
class TranspositionCipher:
    def __init__(self, rails:int=3, keyword:str="hack")->None:
        """Initializer of the Transposition Cipher of each type
        :param rails: number of rails for rail fence cipher (zig-zag cipher). Default set to 3
        :param keyword: Keyword use for column cipher. Default set to 'hack'"""
        self._rails = rails
        self._keyword = keyword
        self.text = ""
        self._table=[]
        self.default_marker = '*+!'
        self._zig_zag_text = ""

    @property
    def rails(self)->int:
        return self._rails

    @rails.setter
    def rails(self, value:int)->None:
        if not isinstance(value, int):
            print("TypeError: could not set a new rails number due to type error")
            return None
        self._rails = value

    @property
    def keyword(self)->str:
        return self._keyword

    @keyword.setter
    def keyword(self, value:str)->None:
        if not isinstance(value, str):
            print("TypeError: could not set a new keyword due to type error")
            return None
        self._keyword = value

    @staticmethod
    def __fill_zig_zag_table(text:str, rails:int, marker:str="*+!")->list:
        """Fill a list with '*+!' to mark the number of character"""
        _table = []
        for _ in range(rails):
            _table.append([marker for _ in text])
        return _table

    def _create_cipher_rails(self, cipher:str, rails_size:Tuple[int])->list:
        """Get cipher table as the table generated for plain text encryption"""
        rails_nb = len(rails_size)
        space_between_item_in_rail = 2*rails_nb -2
        correction_to_apply_on_rail_space = 0
        _table = self.__fill_zig_zag_table(cipher, rails_nb)
        _index_table = 0
        _index_sub_table = 0
        rail_size_index = 0
        shifting_index = 0
        previous_char_position = 0
        for char in cipher:
            # first char is H so no issue, then second char is o , but what is its position ? we knnow it is 4 in the rail 1
            # this table describe the rails behavior:
            #  ##############
            #  2   3   4   5
            #  --------------
            #  2   4   6   8
            #  2   2   4   6
            #      4   2   4
            #          6   2
            #              8
            # to know on the position depending on the rails number: if rails is 2: 2*2-2=2 if rails 3: 2*3-2=4 if rails 4: 2*4-2=6
            
            # we start on rail 1 
            _table[_index_table][_index_sub_table] = char
            previous_char_position = _index_sub_table
            _index_sub_table = previous_char_position + space_between_item_in_rail + correction_to_apply_on_rail_space
            if rail_size_index == rails_size[_index_table]-1:
                rail_size_index = 0
                _index_table +=1
                correction_to_apply_on_rail_space = correction_to_apply_on_rail_space -2 if (space_between_item_in_rail+correction_to_apply_on_rail_space)>2 else 0
                previous_char_position = 0
                shifting_index += 1
                _index_sub_table = shifting_index
            else:
                rail_size_index +=1

        return _table

    @staticmethod
    def get_zig_zag_decrypted_text(cipher_tables:List[List[str]], text_length:int)->str:
        text = ""
        rails_counter = 0 # rise to reach self.rails
        bottom_or_down = False # False down, True raise
        #index =0 # as long we going up or down index stay the same
        rails_nb = len(cipher_tables)
        for index in range(text_length):
            text = text + cipher_tables[rails_counter][index]
            if bottom_or_down: # True so go up
                if rails_counter == 0:
                    bottom_or_down = False
                    rails_counter +=1
                else:
                    rails_counter -=1
            else: # go down
                if rails_counter == rails_nb-1:
                    bottom_or_down = True
                    rails_counter -=1
                else:
                    rails_counter +=1

        return text

    def _get_each_rails_length(self)->tuple:
        return tuple(len("".join(rail).replace(self.default_marker,"")) for rail in self._table)
    
    def _zig_zag_order(self)->list:
        _table = self.__fill_zig_zag_table(self.text, self.rails, self.default_marker)
        self._zig_zag_text = ""
        rails_counter = 0 # rise to reach self.rails
        bottom_or_down = False # False down, True raise
        for index, char in enumerate(self.text):
            _table[rails_counter][index] = char
            if bottom_or_down: # True so go up
                if rails_counter == 0:
                    bottom_or_down = False
                    rails_counter +=1
                else:
                    rails_counter -=1
            else: # go down
                if rails_counter == self.rails-1:
                    bottom_or_down = True
                    rails_counter -=1
                else:
                    rails_counter +=1
        return _table

    def rails_fence_cipher(self, text:str, rails:int=3)->str:
        """Encrypt a message using the rails fence algorithm to get a cipher"""
        # update
        self.text = text
        self._rails = rails
        self._table = self._zig_zag_order()
        non_clean_cipher = "".join(list(chain.from_iterable(self._table)))
        return non_clean_cipher.replace("*+!","")

    def from_rails_fence_cipher(self, cipher:str, rails:int=3)->str:
        """Decrypt a zig zag cipher using the rails fence algorithm to get the message"""
        # update
        self.text = cipher
        self._rails = rails
        self._table = self._zig_zag_order()
        rails_size = self._get_each_rails_length()
        cipher_tables = self._create_cipher_rails(cipher, rails_size)
        return self.get_zig_zag_decrypted_text(cipher_tables, len(self.text))

    def columns_cipher(self, plaintext: str, keyword: str=None) -> str:
        if isinstance(keyword, str):
            self._keyword = keyword
        
        # Each column will contain a string of characters read at interval `key`
        key = len(self._keyword)
        columns = [''] * key
        for col in range(key):
            pointer = col
            while pointer < len(plaintext):
                columns[col] += plaintext[pointer]
                pointer += key

        # order by keyword using ord and char
        # Example for 'HACK': enumerate gives [(0, 'H'), (1, 'A'), (2, 'C'), (3, 'K')]
        # Sorting by character gives: [(1, 'A'), (2, 'C'), (0, 'H'), (3, 'K')]
        col_order = [index for index, _ in sorted(enumerate(keyword), key=lambda x: x[1])]

        # 3. Join columns in the sorted keyword order
        return "".join(columns[col_idx] for col_idx in col_order)

    def colums_cipher_numpy(self, plaintext: str, keyword: str=None, pad_char: str = "X") -> str:
        if isinstance(keyword, str):
            self._keyword = keyword
        #In historical cryptography, spaces were often removed because word boundaries make ciphers easier 
        # to crack via frequency analysis. Cryptanalysts can use spaces to identify common two-letter 
        # or three-letter words (in, on, the, and).
        clean_text = plaintext.replace(" ", "")
        num_cols = len(self._keyword)
        
        # 2. Add padding to make the text fit cleanly into a grid (numpy matrice are rectangle so a 4 cols 
        # and n line can not have only 1 value at the last line, so left cell must be filled: pad_char.
        # e.g: Transpostion is 13 word and keyword 4 so 4 cols. 13/4=3 but 1 left so 3 empty cells left)
        pad_len = (num_cols - (len(clean_text) % num_cols)) % num_cols
        padded_text = clean_text + (pad_char * pad_len)
        
        # 3. Create 2D Matrix (Grid)
        # Shape: (Number of Rows, Number of Columns)
        grid = np.array(list(padded_text)).reshape(-1, num_cols)
        
        # 4. Get alphabetical column order from keyword
        # Example for 'HACK': list('HACK') -> ['H', 'A', 'C', 'K']
        # np.argsort() returns indices that would sort the array -> [1, 2, 0, 3] (A, C, H, K)
        col_order = np.argsort(list(self._keyword))
        
        # 5. Extract columns in sorted order and flatten
        # grid[:, col_order] reorders the columns
        # .T transposes so we read column-by-column
        sorted_grid = grid[:, col_order]
        
        return "".join(sorted_grid.T.flatten())

    def from_column_cipher_numpy(self, ciphertext: str, keyword: str=None) -> str:
        if isinstance(keyword, str):
            self._keyword = keyword
        num_cols = len(self._keyword)
        num_rows = len(ciphertext) // num_cols
        
        # 1. Fill grid column-by-column
        grid = np.array(list(ciphertext)).reshape(num_cols, num_rows).T
        
        # 2. Calculate inverse column order
        # NOTE: [H A C K] == [0 1 2 3] this is current index of each letter before order
        # order: [A C H K] == [1 2 0 3] so in this list the value are the index value of 'HACK' in the list on top in their new position due alphabetic order
        #  this is what is inside col_order =[1 2 0 3] so ACHK (index kept)
        #  by creating inverse_order, we are trying to do the shuffle n oppsite side, so get back to 'HACK' nnot anymore 'ACHK'
        # so we got: we try to find whom where on the 0 index then the 1 index then 2.. [I am lookig for 0: from previous 0 is now on index 2, 1 is now on index 0, 2 is now on index 1, same]
        # so [2, 0, 1, 3] this what we get with inverse_order. thanks to that and the transpose we got original message
        col_order = np.argsort(list(self._keyword))
        inverse_order = np.argsort(col_order)

        # 3. Restore original column positions and read row-by-row
        restored_grid = grid[:, inverse_order]
        return "".join(restored_grid.flatten()) # to get one line, take line by line in respect of the column order


class MultiplicationCipher:
    def __init__(self, key: int, alphabet_size: int = 26):
        if math.gcd(key, alphabet_size) != 1:
            raise ValueError(
                f"Invalid key '{key}'! Key and alphabet size ({alphabet_size}) "
                f"must be coprime (gcd(k, m) = 1)."
            )
        self.key = key
        self.m = alphabet_size
        self.mod_inverse = pow(self.key, -1, self.m)

    def encrypt(self, plaintext: str) -> str:
        ciphertext = []
        for char in plaintext.upper():
            if char.isalpha():
                p = ord(char) - ord('A')
                c = (p * self.key) % self.m
                ciphertext.append(chr(c + ord('A')))
            else:
                ciphertext.append(char)
        return "".join(ciphertext)

    def decrypt(self, ciphertext: str) -> str:
        plaintext = []
        for char in ciphertext.upper():
            if char.isalpha():
                c = ord(char) - ord('A')
                p = (c * self.mod_inverse) % self.m
                plaintext.append(chr(p + ord('A')))
            else:
                plaintext.append(char)
        return "".join(plaintext)


class AffineCipher:
    def __init__(self, a: int, b: int, alphabet_size: int = 26):
        if math.gcd(a, alphabet_size) != 1:
            raise ValueError(
                f"Invalid key 'a'={a}! Must be coprime to alphabet size ({alphabet_size})."
            )
        self.a = a
        self.b = b
        self.m = alphabet_size
        self.a_inv = pow(self.a, -1, self.m)

    def encrypt(self, text: str) -> str:
        result = []
        for char in text.upper():
            if char.isalpha():
                p = ord(char) - ord('A')
                c = (self.a * p + self.b) % self.m
                result.append(chr(c + ord('A')))
            else:
                result.append(char)
        return "".join(result)

    def decrypt(self, text: str) -> str:
        result = []
        for char in text.upper():
            if char.isalpha():
                c = ord(char) - ord('A')
                p = (self.a_inv * (c - self.b)) % self.m
                result.append(chr(p + ord('A')))
            else:
                result.append(char)
        return "".join(result)


class SimpleSubstitutionCipher:
    ENGLISH_FREQ_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

    def __init__(self, key: str = None):
        self.alphabet = string.ascii_uppercase
        
        if key:
            self.key = key.upper()
        else:
            # Generate a random substitution key
            key_list = list(self.alphabet)
            random.shuffle(key_list)
            self.key = "".join(key_list)

        # Build translation tables for high-speed conversion
        self.encrypt_table = str.maketrans(self.alphabet, self.key)
        self.decrypt_table = str.maketrans(self.key, self.alphabet)

    def encrypt(self, text: str) -> str:
        return text.upper().translate(self.encrypt_table)

    def decrypt(self, text: str) -> str:
        return text.upper().translate(self.decrypt_table)

    @staticmethod
    def load_file_dictionary(filepath: str = "englisch_words_alpha.txt") -> set[str]:
        with open(filepath, "r", encoding="utf-8") as f:
            return {
                line.strip().upper() for line in f if line.strip().isalpha()
            }

    @classmethod
    def break_cipher_with_freq_and_dict(cls, ciphertext: str) -> tuple[str, dict]:
        """Breaks a substitution cipher using frequency analysis and dictionary matching. -> NOT WORKING WELL FOR BREAKING Cipher as dictionary is too big"""
        
        # Count letter frequencies in ciphertext
        letters_only = [c for c in ciphertext.upper() if c.isalpha()]
        counts = collections.Counter(letters_only)
        
        # Sort ciphertext letters by observed frequency
        cipher_freq_order = [pair[0] for pair in counts.most_common()]

        # Build initial mapping based purely on English letter frequency
        mapping = {}
        for c_char, p_char in zip(cipher_freq_order, cls.ENGLISH_FREQ_ORDER):
            mapping[c_char] = p_char

        # Add unmapped letters
        for char in string.ascii_uppercase:
            if char not in mapping:
                mapping[char] = "?"

        def decrypt_with_mapping(text: str, current_map: dict) -> str:
            res = []
            for char in text.upper():
                if char in current_map:
                    res.append(current_map[char])
                else:
                    res.append(char)
            return "".join(res)

        # Refine mapping using Dictionary Lookups
        words = re.findall(r"\b[A-Z]+\b", ciphertext.upper())
        
        for word in words:
            partially_decrypted = decrypt_with_mapping(word, mapping)
            
            # Check against dictionary for candidate matches
            DICTIONARY = cls.load_file_dictionary()
            for dict_word in DICTIONARY:
                if len(dict_word) == len(word):
                    # Count matching characters
                    matches = sum(1 for p, d in zip(partially_decrypted, dict_word) if p == d)
                    
                    # If word is a near match (e.g., 80%+ match), adapt key mapping
                    if matches >= len(word) - 1:
                        for c_char, d_char in zip(word, dict_word):
                            mapping[c_char] = d_char

        cracked_text = decrypt_with_mapping(ciphertext, mapping)
        return cracked_text, mapping

    @staticmethod
    def get_word_pattern(word: str) -> tuple[int, ...]:
        """Converts a word into a canonical numerical pattern.

        Example: 'MISSISSIPPI' -> (0, 1, 2, 2, 1, 2, 2, 1, 3, 3, 1)
        """
        word = word.upper()
        seen = {}
        pattern = []
        next_num = 0

        for char in word:
            if char not in seen:
                seen[char] = next_num
                next_num += 1
            pattern.append(seen[char])

        return tuple(pattern)

    @classmethod
    def build_pattern_dictionary(
        cls, dictionary: set[str]
    ) -> dict[tuple[int, ...], list[str]]:
        """Groups dictionary words by their structural word pattern."""
        pattern_dict = collections.defaultdict(list)
        for word in dictionary:
            word_clean = word.upper().strip()
            if word_clean.isalpha():
                pattern = cls.get_word_pattern(word_clean)
                pattern_dict[pattern].append(word_clean)
        return pattern_dict

    # NOTE: Good but when dictionary is too big decryption hacking solution is harder to find !
    @classmethod
    def break_cipher_with_word_pattern(
        cls, cipher_text: str, dictionary: set[str]
    ) -> tuple[str, dict[str, list[str]], dict[str, str]]:
        """We plain text has a word pattern which is kept even after creating the cipher.
        e.g: plain_text:MISSISIPI (we can see they are letter repeated many time)
         from this we can get the world pattern as: MISSISIPI: 0.1.2.2.1.2.1.3.1
         so the decrypted word can be anything which respect the same word pattern !
         let say the cipher of MISSISIPI is AOUUOUOLO. So the cipher as the same number of letter
         as we use a monoalphabetic substitution cipher algo (I have done it randomly :-p).
         Cipher pattern: AOUUOUOLO is 0.1.2.2.1.2.1.3.1 (which is the same pattern as teh plain text word).
         So from this fact, to do the decryption, we just need to have a database of word map with their word pattern
         and for each word found in our cipher message we check if the encrypted pattern match with one of our word
         pattern in our database. To make it more complete, for each encrypted word, we map it with all word found in 
         our database which match with its pattern (dict[str,list]), so that it give more possibility for the user to guess the message.
         But we need to propose also a single solution. To do so, for each word pattern found, we will match the cipher letter with
         each corresponding letter found in each word pattern. and intersect those candidate character mappings across all words 
         in the message. By discarding candidate mappings that create conflicting letter assignments (since simple substitution 
         is a 1-to-1 bijection), we narrow down the possibilities until a single, fully consistent cipher key emerges.

        :param cipher_text: encrypted message to decrypt (should be encrypted using substitution algo)
        :param dictionary: Set of all words we know (here english word)
        :returns:
            - Decrypted text proposal
            - Candidates map: dict[cipher_word, list[candidate_plain_words]]
            - Solved cipher key: dict[cipher_char, plain_char]
        """
        # Build pattern database
        pattern_db = cls.build_pattern_dictionary(dictionary)

        # Extract unique cipher words
        cipher_words = re.findall(r"\b[A-Z]+\b", cipher_text.upper())

        # Find candidates for each cipher word based on pattern
        word_candidates: dict[str, list[str]] = {}
        for c_word in set(cipher_words):
            pattern = cls.get_word_pattern(c_word)
            word_candidates[c_word] = pattern_db.get(pattern, [])

        # Filter character mappings using intersection consistency
        # For each cipher letter, track set of valid plaintext letter candidates
        letter_mapping: dict[str, set[str]] = {
            c: set(string.ascii_uppercase) for c in string.ascii_uppercase
        }

        for c_word, candidates in word_candidates.items():
            if not candidates:
                continue

            # Accumulate possible plain letters for each position in this word
            pos_candidates = [set() for _ in range(len(c_word))]
            for candidate in candidates:
                for idx, plain_char in enumerate(candidate):
                    pos_candidates[idx].add(plain_char)

            # Intersect with global letter mappings
            for idx, c_char in enumerate(c_word):
                letter_mapping[c_char] &= pos_candidates[idx] # ere it is as A = A.intersection(B) so we take only values in A and B

        # Build single deterministic key map (taking unique/most constrained matches)
        solved_key: dict[str, str] = {}
        changed = True

        # Iteratively reduce 1-to-1 letter mappings
        while changed:
            changed = False
            for c_char, candidates in letter_mapping.items():
                if c_char not in solved_key and len(candidates) == 1:
                    resolved_plain = next(iter(candidates))
                    solved_key[c_char] = resolved_plain
                    changed = True

                    # Remove resolved letter from all other candidate sets
                    for other_c in letter_mapping:
                        if other_c != c_char:
                            letter_mapping[other_c].discard(resolved_plain)

        # Decrypt message using solved key
        decrypted_chars = []
        for char in cipher_text.upper():
            if char in solved_key:
                decrypted_chars.append(solved_key[char])
            elif char.isalpha():
                decrypted_chars.append("?")  # Unresolved character fallback
            else:
                decrypted_chars.append(char)

        decrypted_text = "".join(decrypted_chars)

        return decrypted_text, word_candidates, solved_key

#NOTE: vulnerable to dictionary attack if an english word was used for exmple, you just need to list a collections of all english word and use it as key
class VigenereCipher:
    # Standard English letter frequencies (%)
    ENGLISH_FREQS = {
        'A': 8.2,  'B': 1.5,  'C': 2.8,  'D': 4.3,  'E': 12.7, 'F': 2.2,  'G': 2.0,
        'H': 6.1,  'I': 7.0,  'J': 0.15, 'K': 0.77, 'L': 4.0,  'M': 2.4,  'N': 6.7,
        'O': 7.5,  'P': 1.9,  'Q': 0.09, 'R': 6.0,  'S': 6.3,  'T': 9.1,  'U': 2.8,
        'V': 0.98, 'W': 2.4,  'X': 0.15, 'Y': 2.0,  'Z': 0.07
    }


    def __init__(self, key: str):
        self._key = key.upper()

    @property
    def key(self)->str:
        return self._key

    @key.setter
    def key(self, v:str)->None:
        if isinstance(v, str):
            self._key = v

    def encrypt(self, plaintext: str) -> str:
        ciphertext = []
        key_idx = 0
        
        for char in plaintext.upper():
            if char.isalpha():
                p_val = ord(char) - ord('A')
                k_val = ord(self._key[key_idx % len(self._key)]) - ord('A')
                
                c_val = (p_val + k_val) % 26
                ciphertext.append(chr(c_val + ord('A')))
                
                key_idx += 1  # Advance key index only for alphabetic chars
            else:
                ciphertext.append(char)
                
        return "".join(ciphertext)

    def decrypt(self, ciphertext: str) -> str:
        plaintext = []
        key_idx = 0
        
        for char in ciphertext.upper():
            if char.isalpha():
                c_val = ord(char) - ord('A')
                k_val = ord(self._key[key_idx % len(self._key)]) - ord('A')
                
                p_val = (c_val - k_val) % 26
                plaintext.append(chr(p_val + ord('A')))
                
                key_idx += 1
            else:
                plaintext.append(char)
                
        return "".join(plaintext)

    @classmethod
    def _calculate_ic(cls, text: str) -> float:
        """Calculates the Index of Coincidence for a given text segment."""
        N = len(text)
        if N <= 1:
            return 0.0
        
        counts = collections.Counter(text)
        matching_pairs = sum(f * (f - 1) for f in counts.values())
        return matching_pairs / (N * (N - 1))

    @classmethod
    def estimate_key_length_old_version(cls, ciphertext: str, max_key_len: int = 20) -> int:
        """Uses Index of Coincidence to find the most probable key length."""
        best_length = 1
        best_avg_ic = 0.0

        for k_len in range(1, max_key_len + 1):
            column_ics = []
            for col_idx in range(k_len):
                col_text = ciphertext[col_idx::k_len]
                column_ics.append(cls._calculate_ic(col_text))
            
            avg_ic = sum(column_ics) / len(column_ics)
            
            # Target for English text IC is ~0.067
            if avg_ic > best_avg_ic:
                best_avg_ic = avg_ic
                best_length = k_len

        return best_length

    @classmethod
    def kasiski_candidate_factors(cls, text: str, max_key_len: int = 20) -> dict[int, float]:
        """
        Step 1: Scans for repeated 2-letter and 3-letter patterns,
        calculates distance gaps, and scores candidate key lengths by factor frequency.
        """
        factor_scores = collections.defaultdict(float)
        
        # Test pattern lengths of 3 (trigrams) and 2 (bigrams for very short text)
        for seq_len in (3, 2):
            patterns = collections.defaultdict(list)
            for i in range(len(text) - seq_len + 1):
                seq = text[i:i + seq_len]
                patterns[seq].append(i)
            
            # Filter sequences that appear 2+ times
            repeats = {seq: pos for seq, pos in patterns.items() if len(pos) > 1}
            
            if repeats:
                for seq, positions in repeats.items():
                    # Calculate gaps between consecutive occurrences
                    for i in range(len(positions) - 1):
                        gap = positions[i + 1] - positions[i]
                        
                        # Find all factors of the gap up to max_key_len
                        for factor in range(2, max_key_len + 1):
                            if gap % factor == 0:
                                # Weight trigram matches higher than bigram matches
                                weight = 2.0 if seq_len == 3 else 1.0
                                factor_scores[factor] += weight
                
                # Stop checking 2-grams if 3-grams yielded clear patterns
                if seq_len == 3 and factor_scores:
                    break

        # Normalize factor scores between 0.0 and 1.0
        if factor_scores:
            max_val = max(factor_scores.values())
            return {k: v / max_val for k, v in factor_scores.items()}
        return {}

    @classmethod
    def estimate_key_length(cls, ciphertext: str, max_key_len: int = 20) -> int:
        """
        Combines IC analysis with Kasiski pattern spacing to reliably estimate
        key length—even on texts shorter than 100 characters.
        """
        clean_text = [c.upper() for c in ciphertext if c.isalpha()]
        text_len = len(clean_text)
        
        if text_len == 0:
            return 1

        # Get Kasiski factor scores
        kasiski_scores = cls.kasiski_candidate_factors(clean_text, max_key_len)

        # Compute Average Column IC for each candidate length
        ic_scores = {}
        for k_len in range(1, max_key_len + 1):
            col_ics = []
            for col in range(k_len):
                col_text = clean_text[col::k_len]
                col_ics.append(cls._calculate_ic(col_text))
            
            avg_ic = sum(col_ics) / len(col_ics)
            ic_scores[k_len] = avg_ic

        # Hybrid Scoring System
        # Adjust weight based on text length: give Kasiski more weight on short text
        kasiski_weight = 0.6 if text_len < 100 else 0.3
        ic_weight = 1.0 - kasiski_weight

        combined_scores = {}
        for k_len in range(1, max_key_len + 1):
            ic_val = ic_scores[k_len]
            k_val = kasiski_scores.get(k_len, 0.0)
            
            # Combined hybrid score
            combined_scores[k_len] = (ic_val * ic_weight) + (k_val * kasiski_weight)

        # Pick candidate with the highest combined score
        best_length = max(combined_scores, key=combined_scores.get)
        
        return best_length

    @classmethod
    def solve_caesar_column(cls, col_text: str) -> tuple[str, float]:
        """Finds the best single-letter key for a column using Chi-Squared scoring."""
        best_key_char = 'A'
        lowest_chi_squared = float('inf') # Start with the highest possible number
        total_chars = len(col_text)

        for shift in range(26):
            # Decrypt column using shift
            decrypted_col = [
                chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                for char in col_text
            ]
            
            counts = collections.Counter(decrypted_col)
            chi_squared = 0.0

            # Calculate Chi-Squared fit against standard English frequencies
            for char in string.ascii_uppercase:
                expected = (cls.ENGLISH_FREQS[char] / 100.0) * total_chars
                observed = counts[char]
                chi_squared += ((observed - expected) ** 2) / (expected + 1e-6) # 1e-6 prevent ZeroDivisionError: float division by zero

            if chi_squared < lowest_chi_squared:
                lowest_chi_squared = chi_squared
                best_key_char = chr(shift + ord('A'))

        return best_key_char, lowest_chi_squared

    @classmethod
    def crack(cls, ciphertext: str, max_key_len: int = 20) -> tuple[str, str]:
        """Executes the complete Vigenère cracking pipeline."""
        # Clean text for statistical operations (keep only letters, uppercase)
        clean_text = [c.upper() for c in ciphertext if c.isalpha()]
        
        # Find Key Length
        key_length = cls.estimate_key_length(clean_text, max_key_len)
        
        # Slice into columns and solve each Caesar cipher
        recovered_key_chars = []
        for col_idx in range(key_length):
            # Slice into sub-text
            col_text = clean_text[col_idx::key_length]
            
            # Solve column shift
            key_char, _ = cls.solve_caesar_column(col_text)
            recovered_key_chars.append(key_char)

        recovered_key = "".join(recovered_key_chars)
        
        decrypted_text = cls.decrypt(ciphertext, recovered_key)

        return recovered_key, decrypted_text

if __name__ == "__main__":
    message= "This is Python Hacking Session 1 we are doing Reverse Cipher."
    alpha_cipher = "Gsrh rh Kbgslm Szxprmt Hvhhrlm 1 dv ziv wlrmt Ivevihv Xrksvi."
    re_cipher= ReverseCipher.reverse_cipher(message)
    print(re_cipher)
    print(ReverseCipher.reverse_cipher(re_cipher)) # function is both decryption and encryption
    print("reverse alphabetic:"+ ReverseCipher.atbash_cipher(alpha_cipher)) # function is both decryption and encryption
    print(f"ceasar cipher alpha: {CaesarCipherModel.ceasar_cipher_alpha("ZBU")}")
    print(f"ceasar cipher alpha: {CaesarCipherModel.ceasar_cipher_alpha("CEX", is_encrypted=False)}") # we should get ZBU
    print(f"ceasar cipher string: {CaesarCipherModel.ceasar_cipher_string("ZBU23")}")
    print(f"ceasar cipher string: {CaesarCipherModel.ceasar_cipher_string("cEX56",is_encrypted=False)}")
    cipher, model_before_shift, model_after_shift, translation_table = CaesarCipherModel.caesar_cipher_string_v2("ZBU23")
    print("### ceasar cipher string: {0}".format(cipher)) # we got CEX56 instead of cEX56 due to the fact that with teh new table and way after Z come ABC and not directly abc from lower case
    print("### ceasar cipher model before shift: {0}".format(model_before_shift))
    print("### ceasar cipher model after shift : {0}".format(model_after_shift))
    #print("### ceasar cipher string translation table: {0}".format(translation_table))
    print(f"ceasar cipher string: {CaesarCipherModel.ceasar_cipher_string(message)}")
    caesar_cipher = "Wklv.lv.S2wkrq.Kdfnlqj.Vhvvlrq.4.zh.duh.grlqj.Uhyhuvh.FlskhuB" # solution is message variable on top
    print("####################################################################################")
    print("################# BRUTE FORCE A CIPHER KNOWN FOR CAESAR CIPHER #####################")
    print("####################################################################################")
    #CaesarCipherModel.brute_force_decrypt_caesar_cipher(caesar_cipher) # we found that we can read the message when key is 3, so from that we can improve the decryption with a more precise model.
    print("####################################################################################")
    print("#################          Test Transposition Cipher           #####################")
    print("####################################################################################")
    transpostio_cipher = TranspositionCipher()
    plain_text = "Richie tu as bien galere !"
    zig_zag_cipher = transpostio_cipher.rails_fence_cipher(plain_text)
    print(f"{zig_zag_cipher=}")
    decrypted_cipher = transpostio_cipher.from_rails_fence_cipher(zig_zag_cipher)
    print(f"{decrypted_cipher=}")
    plain_text_2="TRANSPOSITION"
    cols_cipher = transpostio_cipher.colums_cipher_numpy(plain_text_2)
    print(f"{cols_cipher=}")
    decrypted_cols_cipher = transpostio_cipher.from_column_cipher_numpy(cols_cipher)
    print(f"{decrypted_cols_cipher=}")

    print("####################################################################################")
    print("#################          Simple Substitution Cipher           ####################")
    print("####################################################################################")
    plaintext = (
            "THIS IS AN EXAMPLE OF FREQUENCY ANALYSIS BREAKING A SIMPLE "
            "SUBSTITUTION CIPHER USING PYTHON DICTIONARY LOOKUPS"
        )

    # Encrypt text with a random key
    cipher_object = SimpleSubstitutionCipher()
    cipher_text = cipher_object.encrypt(plaintext)

    print("=== CIPHERTEXT ===")
    print(cipher_text)
    print()

    # Crack ciphertext automatically
    recovered_plaintext, key_mapping = cipher_object.break_cipher_with_freq_and_dict(cipher_text) # really bad :-) 

    print("=== RECOVERED PLAINTEXT ===")
    print(recovered_plaintext)
    print()

    print("=== ACCURACY CHECK ===")
    matches = sum(1 for p, r in zip(plaintext, recovered_plaintext) if p == r)
    accuracy = (matches / len(plaintext)) * 100
    print(f"Accuracy: {accuracy:.2f}%")

    print("=== WORD PATTERN HACKING===")
    plain_text_easy = "MISSISSIPPI IS AN EXAMPLE OF WORD PATTERN ANALYSIS"
    cipher_text_easy = "OUEEIEEIPPE IE AN EXAMRLE OE VOKD RAJJEKN ANALYEIE"
    cipher_text_easy = cipher_object.encrypt(plain_text_easy)
    dictionary_light = {
    "THIS", "IS", "AN", "EXAMPLE", "OF", "WORD", "PATTERN", 
    "ANALYSIS", "MISSISSIPPI", "SOLVER", "CIPHER", "MESSAGE"
    }
    decrypted, word_map, key = cipher_object.break_cipher_with_word_pattern(
    cipher_text_easy, dictionary_light
)

    print("=== CANDIDATE WORDS PER PATTERN ===")
    for c_word, candidates in word_map.items():
        print(f"Cipher Word '{c_word}': {candidates}")

    print("\n=== RECOVERED PLAINTEXT ===")
    print(decrypted)

