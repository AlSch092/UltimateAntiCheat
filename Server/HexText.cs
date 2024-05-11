//UltimateAnticheat Server - By AlSch092 @ Github
using System;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.Text;

namespace UACServer
{
    public static class HexText
    {
        private static readonly Random sRandom = new Random();

        private static readonly char[] sHexChars = new char[]
        {
            'A','B','C','D','E','F',
            '0','1','2','3','4','5','6','7','8','9'
        };

        public static char GetHexValue(int value)
        {
            return value < 10 ? (char)(value + 48) : (char)(value - 10 + 65);
        }

        public static bool IsHexChar(char hex)
        {
            return hex >= '0' && hex <= '9' || hex >= 'A' && hex <= 'F' || hex >= 'a' && hex <= 'f';
        }

        public static string ToString(byte[] value)
        {
            int arrayLen = value.Length * 3;
            int arrayPos = 0;
            char[] array = new char[arrayLen];

            for (int i = 0; i < arrayLen; i += 3)
            {
                byte b = value[arrayPos++];
                array[i] = GetHexValue(b / 16);
                array[i + 1] = GetHexValue(b % 16);
                array[i + 2] = ' ';
            }

            return new string(array, 0, array.Length - 1);
        }
        public static string ToStringAscii(byte[] value)
        {
            char[] array = new char[value.Length];

            for (int i = 0; i < value.Length; i++)
            {
                char temp = (char)value[i];
                array[i] = temp >= ' ' && temp <= '~' ? temp : '.';
            }

            return new string(array);
        }

        public static byte[] ToBytes(string packet, bool parse = true)
        {
            if (parse)
            {
                StringBuilder sr = new StringBuilder();

                foreach (char c in packet)
                {
                    if (IsHexChar(c))
                        sr.Append(c);
                    else if (c == '*')
                        sr.Append(sHexChars[sRandom.Next(0, 15)]);
                }

                packet = sr.ToString();
            }

            return SoapHexBinary.Parse(packet).Value;
        }
    }
}
