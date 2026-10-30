using System.Numerics;
using System.Security.Cryptography;

namespace Package02.Primality;

public static class RandomIntegers
{
    public static BigInteger Below(BigInteger exclusiveUpperBound)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(exclusiveUpperBound);
        if (exclusiveUpperBound == 1)
        {
            return 0;
        }

        long bits = (exclusiveUpperBound - 1).GetBitLength();
        int byteCount = checked((int)((bits + 7) / 8));
        byte[] bytes = new byte[byteCount];
        int excessBits = (int)(byteCount * 8L - bits);
        BigInteger candidate;
        do
        {
            RandomNumberGenerator.Fill(bytes);
            bytes[^1] &= (byte)(0xff >> excessBits);
            candidate = new BigInteger(bytes, isUnsigned: true, isBigEndian: false);
        }
        while (candidate >= exclusiveUpperBound);

        return candidate;
    }

    public static BigInteger OddWithBitLength(int bitLength)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(bitLength, 2);
        BigInteger highBit = BigInteger.One << (bitLength - 1);
        return Below(highBit) | highBit | BigInteger.One;
    }
}
