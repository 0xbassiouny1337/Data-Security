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
            char[] encryptedChars = new char[plainText.Length];
            for (int index = 0; index < plainText.Length; index++)
            {
                encryptedChars[index] = ShiftCharacter(plainText[index], key);
            }
            return new string(encryptedChars);
        }

        public string Decrypt(string cipherText, int key)
        {
            int invKey = (-key + 26) % 26;
            return Encrypt(cipherText, invKey);
        }

        public int Analyse(string plainText, string cipherText)
        {
            if (plainText.Length != cipherText.Length)
            {
                return -1;
            }

            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            int? detectedKey = null;
            for (int pos = 0; pos < plainText.Length; pos++)
            {
                if (char.IsLetter(plainText[pos]))
                {
                    if (!char.IsLetter(cipherText[pos]))
                    {
                        return -1;
                    }
                    int currentKey = (cipherText[pos] - plainText[pos] + 26) % 26;
                    if (detectedKey == null)
                    {
                        detectedKey = currentKey;
                    }
                    else if (detectedKey != currentKey)
                    {
                        return -1;
                    }
                }
            }
            if (detectedKey == null)
            {
                return -1;
            }
            return detectedKey.Value;
        }

        private char ShiftCharacter(char ch, int key)
        {
            if (!char.IsLetter(ch))
            {
                return ch;
            }
            char baseLetter = char.IsUpper(ch) ? 'A' : 'a';
            int offset = ch - baseLetter;
            int newOffset = (offset + key + 26) % 26;
            return (char)(baseLetter + newOffset);
        }
    }
}

}
