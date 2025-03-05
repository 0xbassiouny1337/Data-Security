using SecurityLibrary;
using System;

namespace SecurityLibrary
{
    public class Ceaser
    {
        public string Encrypt(string inputText, int shiftKey)
        {
            if (string.IsNullOrEmpty(inputText))
            {
                throw new ArgumentException("Input text cannot be null or empty.", nameof(inputText));
            }

            shiftKey %= 26;
            char[] cipherTextChars = new char[inputText.Length];

            for (int i = 0; i < inputText.Length; i++)
            {
                char currentChar = inputText[i];

                if (char.IsLetter(currentChar))
                {
                    char baseChar = char.IsUpper(currentChar) ? 'A' : 'a';
                    int alphaIndex = currentChar - baseChar;
                    int shiftedIndex = (alphaIndex + shiftKey + 26) % 26;
                    cipherTextChars[i] = (char)(baseChar + shiftedIndex);
                }
                else
                {
                    cipherTextChars[i] = currentChar;
                }
            }

            return new string(cipherTextChars);
        }

        public string Decrypt(string inputText, int shiftKey)
        {
            return Encrypt(inputText, -shiftKey);
        }

        public int Analyse(string plainText, string cipherText)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentException("Plain text cannot be null or empty.", nameof(plainText));
            if (string.IsNullOrEmpty(cipherText))
                throw new ArgumentException("Cipher text cannot be null or empty.", nameof(cipherText));
            if (plainText.Length != cipherText.Length)
                throw new ArgumentException("Plain text and cipher text must be of the same length.");

            int? foundKey = null;
            for (int i = 0; i < plainText.Length; i++)
            {
                char p = plainText[i];
                char c = cipherText[i];

                if (char.IsLetter(p))
                {
                    if (!char.IsLetter(c))
                        throw new ArgumentException("Mismatch: plain text letter does not correspond to a letter in cipher text.");

                    char baseChar = char.IsUpper(p) ? 'A' : 'a';
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


namespace CaesarCipherApp
{
    class Program
    {
        static void Main(string[] args)
        {
            bool continueProgram = true;
            Console.WriteLine("Welcome to the Caesar Cipher App!");

            // Create an instance of the Ceaser class
            Ceaser ceaser = new Ceaser();

            while (continueProgram)
            {
                Console.Write("Type 'E' for Encryption, 'D' for Decryption, or 'A' for Analysis: ");
                string mode = Console.ReadLine()?.Trim().ToUpper();

                if (mode != "E" && mode != "D" && mode != "A")
                {
                    Console.WriteLine("Error: Please enter 'E', 'D', or 'A'.");
                    continue;
                }

                try
                {
                    if (mode == "E")
                    {
                        Console.Write("Enter the message to encrypt: ");
                        string userMessage = Console.ReadLine();
                        if (string.IsNullOrWhiteSpace(userMessage))
                        {
                            Console.WriteLine("Error: The message cannot be empty.");
                            continue;
                        }

                        Console.Write("Enter the numeric key (integer value): ");
                        string keyInput = Console.ReadLine();
                        if (!int.TryParse(keyInput, out int numericKey))
                        {
                            Console.WriteLine("Error: Invalid key. Please provide a valid integer.");
                            continue;
                        }

                        // Use the Ceaser instance to encrypt
                        string encryptedMessage = ceaser.Encrypt(userMessage, numericKey);
                        Console.WriteLine($"\nEncrypted Message: {encryptedMessage}");
                    }
                    else if (mode == "D")
                    {
                        Console.Write("Enter the message to decrypt: ");
                        string userMessage = Console.ReadLine();
                        if (string.IsNullOrWhiteSpace(userMessage))
                        {
                            Console.WriteLine("Error: The message cannot be empty.");
                            continue;
                        }

                        Console.Write("Enter the numeric key (integer value): ");
                        string keyInput = Console.ReadLine();
                        if (!int.TryParse(keyInput, out int numericKey))
                        {
                            Console.WriteLine("Error: Invalid key. Please provide a valid integer.");
                            continue;
                        }

                        // Use the Ceaser instance to decrypt
                        string decryptedMessage = ceaser.Decrypt(userMessage, numericKey);
                        Console.WriteLine($"\nDecrypted Message: {decryptedMessage}");
                    }
                    else if (mode == "A")
                    {
                        Console.Write("Enter the plain text: ");
                        string plainText = Console.ReadLine();
                        if (string.IsNullOrWhiteSpace(plainText))
                        {
                            Console.WriteLine("Error: The plain text cannot be empty.");
                            continue;
                        }

                        Console.Write("Enter the cipher text: ");
                        string cipherText = Console.ReadLine();
                        if (string.IsNullOrWhiteSpace(cipherText))
                        {
                            Console.WriteLine("Error: The cipher text cannot be empty.");
                            continue;
                        }

                        // Use the Ceaser instance to analyze
                        int analyzedKey = ceaser.Analyse(plainText, cipherText);
                        Console.WriteLine($"\nThe key is: {analyzedKey}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"An error occurred: {ex.Message}");
                }

                Console.Write("\nProceed? (Y/N): ");
                string proceed = Console.ReadLine()?.Trim().ToUpper();
                if (proceed != "Y")
                {
                    continueProgram = false;
                }
                Console.WriteLine();
            }

            Console.WriteLine("Goodbye!");
        }
    }
}
