using System.Security.Cryptography;

namespace Package01.Padding;

internal static class PaddingCodec
{
    public static byte[] Pad(byte[] input, int blockSize, PaddingMode mode)
    {
        int remainder = input.Length % blockSize;
        int paddingLength = mode == PaddingMode.Zeros && remainder == 0
            ? 0
            : blockSize - remainder;

        byte[] result = new byte[checked(input.Length + paddingLength)];
        input.CopyTo(result, 0);

        if (paddingLength > 0)
        {
            FillPadding(result.AsSpan(input.Length), mode);
        }

        return result;
    }

    public static byte[]? FinalBlock(ReadOnlySpan<byte> remainder, int blockSize, PaddingMode mode)
    {
        if (remainder.Length == 0 && mode == PaddingMode.Zeros)
        {
            return null;
        }

        byte[] block = new byte[blockSize];
        remainder.CopyTo(block);
        FillPadding(block.AsSpan(remainder.Length), mode);
        return block;
    }

    public static int GetUnpaddedLength(ReadOnlySpan<byte> lastBlock, PaddingMode mode)
    {
        if (mode == PaddingMode.Zeros)
        {
            int length = lastBlock.Length;
            while (length > 0 && lastBlock[length - 1] == 0)
            {
                length--;
            }

            return length;
        }

        if (lastBlock.IsEmpty)
        {
            throw new CryptographicException("Ciphertext does not contain a padding block.");
        }

        int count = lastBlock[^1];
        if (count == 0 || count > lastBlock.Length)
        {
            throw new CryptographicException("Invalid padding length.");
        }

        ReadOnlySpan<byte> padding = lastBlock[^count..];
        if (mode == PaddingMode.Pkcs7)
        {
            foreach (byte value in padding)
            {
                if (value != count)
                {
                    throw new CryptographicException("Invalid PKCS7 padding.");
                }
            }
        }
        else if (mode == PaddingMode.AnsiX923)
        {
            foreach (byte value in padding[..^1])
            {
                if (value != 0)
                {
                    throw new CryptographicException("Invalid ANSI X.923 padding.");
                }
            }
        }

        return lastBlock.Length - count;
    }

    private static void FillPadding(Span<byte> padding, PaddingMode mode)
    {
        if (padding.IsEmpty || mode == PaddingMode.Zeros)
        {
            return;
        }

        if (mode == PaddingMode.Iso10126 && padding.Length > 1)
        {
            RandomNumberGenerator.Fill(padding[..^1]);
        }
        else if (mode == PaddingMode.Pkcs7)
        {
            padding.Fill((byte)padding.Length);
        }

        padding[^1] = (byte)padding.Length;
    }
}
