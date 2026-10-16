using Package01.Abstractions;
using Package01.BitOperations;

namespace Package01.Des;

public sealed class DesKeyExpansion : IKeyExpansion
{
    public byte[][] ExpandKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != 8)
        {
            throw new ArgumentException("A DES key must contain eight bytes.", nameof(key));
        }

        byte[] selected = BitUtils.Permute(key, DesTables.KeyPermutation, true, 1);
        ulong packed = 0;
        foreach (byte value in selected)
        {
            packed = (packed << 8) | value;
        }

        uint left = (uint)(packed >> 28);
        uint right = (uint)(packed & 0x0FFFFFFF);
        byte[][] roundKeys = new byte[16][];
        for (int round = 0; round < roundKeys.Length; round++)
        {
            int rotation = DesTables.KeyRotations[round];
            left = RotateLeft28(left, rotation);
            right = RotateLeft28(right, rotation);
            packed = ((ulong)left << 28) | right;
            byte[] combined = new byte[7];
            for (int index = combined.Length - 1; index >= 0; index--)
            {
                combined[index] = (byte)packed;
                packed >>= 8;
            }

            roundKeys[round] = BitUtils.Permute(combined, DesTables.KeyCompression, true, 1);
        }

        return roundKeys;
    }

    private static uint RotateLeft28(uint value, int count) =>
        ((value << count) | (value >> (28 - count))) & 0x0FFFFFFF;
}
