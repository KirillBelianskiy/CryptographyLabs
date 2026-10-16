using Package01.Abstractions;
using Package01.BitOperations;

namespace Package01.Des;

public sealed class DesRoundTransformation : IRoundTransformation
{
    public byte[] Transform(byte[] inputBlock, byte[] roundKey)
    {
        ArgumentNullException.ThrowIfNull(inputBlock);
        ArgumentNullException.ThrowIfNull(roundKey);
        if (inputBlock.Length != 4 || roundKey.Length != 6)
        {
            throw new ArgumentException("DES F requires a four-byte half and a six-byte round key.");
        }

        byte[] expanded = BitUtils.Permute(inputBlock, DesTables.Expansion, true, 1);
        ulong mixed = 0;
        for (int index = 0; index < expanded.Length; index++)
        {
            mixed = (mixed << 8) | (byte)(expanded[index] ^ roundKey[index]);
        }

        byte[] substituted = new byte[4];
        for (int box = 0; box < 8; box++)
        {
            int value = (int)((mixed >> (42 - box * 6)) & 0x3F);
            int row = ((value & 0x20) >> 4) | (value & 1);
            int column = (value >> 1) & 0x0F;
            byte output = DesTables.SBoxes[box][row * 16 + column];
            substituted[box / 2] |= (byte)(output << (box % 2 == 0 ? 4 : 0));
        }

        return BitUtils.Permute(substituted, DesTables.RoundPermutation, true, 1);
    }
}
