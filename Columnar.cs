using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecurityLibrary
{
    public class Columnar
    {
        public string Encrypt(string plainText, List<int> key)
        {
            if (string.IsNullOrEmpty(plainText) || key == null || key.Count == 0)
                return plainText;

            int No_columns = key.Count;
            int No_rows = plainText.Length / No_columns + (plainText.Length % No_columns == 0 ? 0 : 1);
            char?[,] point = new char?[No_rows, No_columns];
            int index = 0;

            for (int i = 0; i < No_rows; i++)
            {
                for (int j = 0; j < No_columns; j++)
                {
                    if (index < plainText.Length)
                        point[i, j] = plainText[index++];
                    else
                        point[i, j] = 'x';
                }
            }

            int availableRows = plainText.Length % No_columns;
            if (availableRows == 0)
                availableRows = No_columns;

            List<(int ColumnValue, int ColumnIndex)> ArrangedKey = new List<(int, int)>();
            for (int i = 0; i < No_columns; i++)
            {
                ArrangedKey.Add((key[i], i));
            }
            ArrangedKey.Sort((x, y) => x.ColumnValue.CompareTo(y.ColumnValue));

            StringBuilder cipherText = new StringBuilder();

            foreach (var value in ArrangedKey)
            {
                int j = value.ColumnIndex;
                for (int i = 0; i < No_rows; i++)
                {
                    if (i == No_rows - 1 && j >= availableRows)
                        continue;
                    cipherText.Append(point[i, j].Value);
                }
            }
            return cipherText.ToString();
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            if (string.IsNullOrEmpty(cipherText) || key == null || key.Count == 0)
                return cipherText;

            int No_columns = key.Count;
            int TextLen = cipherText.Length;
            int No_rows = TextLen / No_columns + (TextLen % No_columns == 0 ? 0 : 1);
            int AvailableCols = TextLen % No_columns;
            if (AvailableCols == 0)
                AvailableCols = No_columns;

            List<(int ColumnValue, int ColumnIndex)> ArrangedKey = new List<(int, int)>();
            for (int i = 0; i < No_columns; i++)
            {
                ArrangedKey.Add((key[i], i));
            }
            ArrangedKey.Sort((x, y) => x.ColumnValue.CompareTo(y.ColumnValue));

            char[,] point = new char[No_rows, No_columns];
            int cipherIndex = 0;
            int sortedIndex = 0;

            foreach (var value in ArrangedKey)
            {
                int colLetters = (sortedIndex < AvailableCols) ? No_rows : No_rows - 1;
                for (int i = 0; i < colLetters; i++)
                {
                    if (cipherIndex < TextLen)
                        point[i, value.ColumnIndex] = cipherText[cipherIndex++];
                }
                sortedIndex++;
            }

            StringBuilder plainText = new StringBuilder();
            for (int i = 0; i < No_rows; i++)
            {
                for (int j = 0; j < No_columns; j++)
                {
                    if (i == No_rows - 1 && j >= AvailableCols)
                        continue;
                    plainText.Append(point[i, j]);
                }
            }
            return plainText.ToString().TrimEnd('x');
        }

        public List<int> Analyse(string plainText, string cipherText)
        {
            if (string.IsNullOrEmpty(plainText) || string.IsNullOrEmpty(cipherText))
                return new List<int>(); // return empty list for invalid input

            int PT_Len = plainText.Length;
            for (int k = 2; k <= PT_Len; k++)
            {
                int No_rows = PT_Len / k + (PT_Len % k == 0 ? 0 : 1);
                int availableRows = (PT_Len % k == 0 ? k : PT_Len % k);

                char[,] point = new char[No_rows, k];
                int indexx = 0;
                for (int i = 0; i < No_rows; i++)
                {
                    for (int j = 0; j < k; j++)
                    {
                        if (indexx < PT_Len)
                            point[i, j] = plainText[indexx++];
                        else
                            point[i, j] = 'x';
                    }
                }

                List<int> indices = Enumerable.Range(0, k).ToList();
                foreach (var P in GetPermutations(indices, k))
                {
                    List<int> PList = P.ToList();
                    StringBuilder candidateCipher = new StringBuilder();
                    for (int i = 0; i < k; i++)
                    {
                        int col = PList[i];
                        for (int r = 0; r < No_rows; r++)
                        {
                            if (r == No_rows - 1 && col >= availableRows)
                                continue;
                            candidateCipher.Append(point[r, col]);
                        }
                    }
                    if (candidateCipher.ToString().Equals(cipherText, StringComparison.OrdinalIgnoreCase))
                    {
                        List<int> key = new List<int>(new int[k]);
                        for (int j = 0; j < k; j++)
                        {
                            int position = PList.IndexOf(j);
                            key[j] = position + 1;
                        }
                        return key;
                    }
                }
            }
            return new List<int>(); // return empty list if no valid key is found
        }

        private IEnumerable<IEnumerable<T>> GetPermutations<T>(IEnumerable<T> list, int length)
        {
            if (length == 1)
                return list.Select(t => new T[] { t });

            return GetPermutations(list, length - 1)
                .SelectMany(t => list.Where(e => !t.Contains(e)),
                            (t1, t2) => t1.Concat(new T[] { t2 }));
        }
    }
}
