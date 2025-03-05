using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser
    {
        public string Encrypt(string plainText, int key)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                throw new ArgumentException("Input text cannot be null or empty.", nameof(plainText));
            }
            key %= 26;
            char[] cipherTextChars = new char[plainText.Length];
            for (int i = 0; i < plainText.Length; i++)
            {
                char currentChar = plainText[i];
                if (char.IsLetter(currentChar))
                {
                    char baseChar = char.IsUpper(currentChar) ? 'A' : 'a';
                    int alphaIndex = currentChar - baseChar;
                    int shiftedIndex = (alphaIndex + key + 26) % 26;
                    cipherTextChars[i] = (char)(baseChar + shiftedIndex);
                }
                else
                {
                    cipherTextChars[i] = currentChar;
                }
            }
            return new string(cipherTextChars);
        }

        public string Decrypt(string cipherText, int key)
        {
            return Encrypt(cipherText, -key);
        }

        public int Analyse(string plainText, string cipherText)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentException("Plain text cannot be null or empty.", nameof(plainText));
            if (string.IsNullOrEmpty(cipherText))
                throw new ArgumentException("Cipher text cannot be null or empty.", nameof(cipherText));
            if (plainText.Length != cipherText.Length)
                throw new ArgumentException("Plain text and cipher text must be of the same length.");

            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            int? foundKey = null;
            for (int i = 0; i < plainText.Length; i++)
            {
                char p = plainText[i];
                char c = cipherText[i];
                if (char.IsLetter(p))
                {
                    if (!char.IsLetter(c))
                        throw new ArgumentException("Mismatch: plain text letter does not correspond to a letter in cipher text.");

                    int computedKey = (c - p + 26) % 26;
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
                throw new ArgumentException("No letters were found to analyze the key.");
            return foundKey.Value;
        }
    }
  }   
