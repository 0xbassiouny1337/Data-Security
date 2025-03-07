/*
Summary:
Encrypt(string plainText, int key): Encrypts the given plainText using the Caesar cipher algorithm with the provided key. The key is normalized to the range 0-25. Non-letter characters remain unchanged.
Decrypt(string cipherText, int key): Decrypts the given cipherText by computing the decryption key as (-key + 26) mod 26 and then encrypting the text with that decryption key.
Analyse(string plainText, string cipherText): Analyzes the provided plainText and cipherText to determine the encryption key used. It processes only letter characters (after converting texts to lowercase) and returns the consistent shift value if found.
ShiftCharacter(char ch, int key): Shifts a single character by the given key if it is a letter; returns non-letter characters unchanged.
*/

using System;

namespace SecurityLibrary
{
    public class Ceaser
    {
        public string Encrypt(string plainText, int key)
        {
            key = key % 26;
            char[] result = new char[plainText.Length];
            for (int i = 0; i < plainText.Length; i++)
            {
                result[i] = ShiftCharacter(plainText[i], key);
            }
            return new string(result);
        }

        public string Decrypt(string cipherText, int key)
        {
            int decryptKey = (-key + 26) % 26;
            return Encrypt(cipherText, decryptKey);
        }

        public int Analyse(string plainText, string cipherText)
        {
            if (plainText.Length != cipherText.Length)
            {
                throw new ArgumentException("Plain text and cipher text must be of the same length.");
            }

            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            int? foundKey = null;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (char.IsLetter(plainText[i]))
                {
                    if (!char.IsLetter(cipherText[i]))
                    {
                        throw new ArgumentException("Mismatch: plain text letter does not correspond to a letter in cipher text.");
                    }
                    int computedKey = (cipherText[i] - plainText[i] + 26) % 26;
                    if (foundKey == null)
                    {
                        foundKey = computedKey;
                    }
                    else if (foundKey != computedKey)
                    {
                        throw new ArgumentException("Inconsistent encryption: different key shifts detected.");
                    }
                }
            }
            if (foundKey == null)
            {
                throw new ArgumentException("No letters were found to analyze the key.");
            }
            return foundKey.Value;
        }

        private char ShiftCharacter(char ch, int key)
        {
            if (!char.IsLetter(ch))
            {
                return ch;
            }
            char baseChar;
            if (char.IsUpper(ch))
            {
                baseChar = 'A';
            }
            else
            {
                baseChar = 'a';
            }
            int alphaIndex = ch - baseChar;
            int shiftedIndex = (alphaIndex + key + 26) % 26;
            char shiftedChar = (char)(baseChar + shiftedIndex);
            return shiftedChar;
        }
    }
}
