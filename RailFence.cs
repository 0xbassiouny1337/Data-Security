using System;
using System.Text;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {

            for (int key = 1; key <= cipherText.Length; key++)
            {
                string encryptedText = Encrypt(plainText, key);
                if (encryptedText.Equals(cipherText, StringComparison.InvariantCultureIgnoreCase))
                    return key;
            }
            return -1;
        }

        public string Encrypt(string plainText, int key)
        {

            plainText = plainText.Replace(" ", "");

            int TexLen = plainText.Length;
            int NO_Cols = TexLen / key;
            int Partial_Col = TexLen % key;
            int Tot_Cols = NO_Cols + (Partial_Col > 0 ? 1 : 0);

            char[,] matrix = new char[key, Tot_Cols];
            int index = 0;

            for (int j = 0; j < Tot_Cols; j++)
            {
                for (int i = 0; i < key; i++)
                {
                    if (index < plainText.Length)
                    {
                        matrix[i, j] = plainText[index++];
                    }
                }
            }

            StringBuilder cipherText = new StringBuilder();
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < Tot_Cols; j++)
                {
                    if (matrix[i, j] != '\0')
                        cipherText.Append(matrix[i, j]);
                }
            }
            return cipherText.ToString();
        }

        public string Decrypt(string cipherText, int key)
        {
            int TexLen = cipherText.Length;
            int NO_Cols = TexLen / key;
            int Partial_Col = TexLen % key;
            int Tot_Cols = NO_Cols + (Partial_Col > 0 ? 1 : 0);

            char[,] matrix = new char[key, Tot_Cols];
            int index = 0;


            for (int i = 0; i < key; i++)
            {
                int RowCells = (i < Partial_Col) ? (NO_Cols + 1) : NO_Cols;
                for (int j = 0; j < RowCells; j++)
                {
                    if (index < cipherText.Length)
                    {
                        matrix[i, j] = cipherText[index++];
                    }
                }
            }

            StringBuilder plainText = new StringBuilder();
            for (int j = 0; j < Tot_Cols; j++)
            {
                for (int i = 0; i < key; i++)
                {
                    if (j < NO_Cols || (j == NO_Cols && i < Partial_Col))
                        plainText.Append(matrix[i, j]);
                }
            }
            return plainText.ToString();
        }
    }
}
