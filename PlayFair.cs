it is good to sumbit the code like this , it won't taken as cheating or Copy others code : using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        private const int MatrixSize = 5;
        private const char FillerChar = 'X';

        public string Encrypt(string plainText, string key)
        {
            if (string.IsNullOrWhiteSpace(plainText))
                throw new ArgumentException("Plain text cannot be null or empty.");
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("Key cannot be null or empty.");

            string refinedKey = CleanInput(key);
            char[,] mat = GenerateKeyMatrix(refinedKey);
            var positionMap = BuildLookup(mat);
            string validPlain = CleanInput(plainText);
            List<string> pairs = CreateDigraphs(validPlain, forEncryption: true);
            StringBuilder result = new StringBuilder();

            foreach (string pair in pairs)
            {
                (int r1, int c1) = positionMap[pair[0]];
                (int r2, int c2) = positionMap[pair[1]];

                if (r1 == r2)
                {
                    result.Append(mat[r1, (c1 + 1) % MatrixSize]);
                    result.Append(mat[r2, (c2 + 1) % MatrixSize]);
                }
                else if (c1 == c2)
                {
                    result.Append(mat[(r1 + 1) % MatrixSize, c1]);
                    result.Append(mat[(r2 + 1) % MatrixSize, c2]);
                }
                else
                {
                    result.Append(mat[r1, c2]);
                    result.Append(mat[r2, c1]);
                }
            }
            return result.ToString();
        }

        public string Decrypt(string cipherText, string key)
        {
            if (string.IsNullOrWhiteSpace(cipherText))
                throw new ArgumentException("Cipher text cannot be null or empty.");
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("Key cannot be null or empty.");

            string refinedKey = CleanInput(key);
            char[,] mat = GenerateKeyMatrix(refinedKey);
            var positionMap = BuildLookup(mat);
            string validCipher = CleanInput(cipherText);
            List<string> pairs = CreateDigraphs(validCipher, forEncryption: false);
            StringBuilder rawResult = new StringBuilder();

            foreach (string pair in pairs)
            {
                (int r1, int c1) = positionMap[pair[0]];
                (int r2, int c2) = positionMap[pair[1]];

                if (r1 == r2)
                {
                    rawResult.Append(mat[r1, (c1 + MatrixSize - 1) % MatrixSize]);
                    rawResult.Append(mat[r2, (c2 + MatrixSize - 1) % MatrixSize]);
                }
                else if (c1 == c2)
                {
                    rawResult.Append(mat[(r1 + MatrixSize - 1) % MatrixSize, c1]);
                    rawResult.Append(mat[(r2 + MatrixSize - 1) % MatrixSize, c2]);
                }
                else
                {
                    rawResult.Append(mat[r1, c2]);
                    rawResult.Append(mat[r2, c1]);
                }
            }
            string rawDecrypted = rawResult.ToString();
            string finalOutput = RemoveExtraneousFillers(rawDecrypted);
            return finalOutput;
        }

        private char[,] GenerateKeyMatrix(string key)
        {
            HashSet<char> seen = new HashSet<char>();
            List<char> list = new List<char>();

            foreach (char ch in key)
            {
                char letter = (ch == 'J') ? 'I' : ch;
                if (!seen.Contains(letter) && letter >= 'A' && letter <= 'Z')
                {
                    seen.Add(letter);
                    list.Add(letter);
                }
            }
            for (char letter = 'A'; letter <= 'Z'; letter++)
            {
                if (letter == 'J')
                    continue;
                if (!seen.Contains(letter))
                {
                    seen.Add(letter);
                    list.Add(letter);
                }
            }
            char[,] matrix = new char[MatrixSize, MatrixSize];
            for (int i = 0; i < MatrixSize * MatrixSize; i++)
                matrix[i / MatrixSize, i % MatrixSize] = list[i];
            return matrix;
        }

        private Dictionary<char, (int row, int col)> BuildLookup(char[,] matrix)
        {
            Dictionary<char, (int, int)> map = new Dictionary<char, (int, int)>();
            for (int r = 0; r < MatrixSize; r++)
                for (int c = 0; c < MatrixSize; c++)
                    map[matrix[r, c]] = (r, c);
            return map;
        }

        private string CleanInput(string input)
        {
            StringBuilder sb = new StringBuilder();
            foreach (char ch in input.ToUpperInvariant())
                if (ch >= 'A' && ch <= 'Z')
                    sb.Append(ch == 'J' ? 'I' : ch);
            return sb.ToString();
        }

        private List<string> CreateDigraphs(string input, bool forEncryption)
        {
            List<string> pairs = new List<string>();
            int index = 0;
            while (index < input.Length)
            {
                char first = input[index];
                char second = ' ';
                if (index + 1 < input.Length)
                {
                    second = input[index + 1];
                    if (forEncryption && first == second)
                    {
                        second = FillerChar;
                        index++;
                    }
                    else
                    {
                        index += 2;
                    }
                }
                else
                {
                    second = FillerChar;
                    index++;
                }
                pairs.Add(new string(new char[] { first, second }));
            }
            return pairs;
        }

        private string RemoveExtraneousFillers(string decryptedText)
        {
            StringBuilder output = new StringBuilder();
            for (int i = 0; i < decryptedText.Length; i++)
            {
                if (decryptedText[i] == FillerChar)
                {
                    if (i == decryptedText.Length - 1)
                        break;
                    else if ((i % 2 != 0) && (decryptedText[i - 1] == decryptedText[i + 1]))
                        continue;
                    else
                        output.Append(decryptedText[i]);
                }
                else
                {
                    output.Append(decryptedText[i]);
                }
            }
            return output.ToString();
        }
    }
}
