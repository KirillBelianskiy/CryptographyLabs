using Package01.Abstractions;
using Package01.Des;

namespace Package01.Deal;

public sealed class DealKeyExpansion : IKeyExpansion
{
    public byte[][] ExpandKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length is not (16 or 24 or 32))
        {
            throw new ArgumentException("A DEAL key must contain 16, 24 or 32 bytes.", nameof(key));
        }

        var cipher = new DesCipher();
        cipher.SetKey(Convert.FromHexString("0123456789ABCDEF"));
        int parts = key.Length / 8;
        int rounds = key.Length == 32 ? 8 : 6;
        byte[][] roundKeys = new byte[rounds][];
        byte[] previous = new byte[8];
        for (int round = 0; round < rounds; round++)
        {
            byte[] block = key.AsSpan(round % parts * 8, 8).ToArray();
            for (int index = 0; index < block.Length; index++)
            {
                block[index] ^= previous[index];
            }

            // The constants are bits 1, 2, 3, 4 counted from the MSB.
            if (round >= parts)
            {
                block[0] ^= (byte)(0x80 >> (round - parts));
            }

            previous = cipher.EncryptBlock(block);
            roundKeys[round] = previous;
        }

        return roundKeys;
    }
}
