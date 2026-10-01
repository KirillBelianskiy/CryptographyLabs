namespace Package01.BitOperations;

public static class BitUtils
{
    private static int GetBit(
        byte[] data,
        int index,
        bool isMsb)
    {
        var byteIndex = index / 8;
        var bitIndexInsideByte = index % 8;

        var physicalBitIndex = isMsb
            ? 7 - bitIndexInsideByte
            : bitIndexInsideByte;

        return (data[byteIndex] >> physicalBitIndex) & 1;
    }

    private static void SetBit(
        byte[] data,
        int index,
        byte value,
        bool isMsb)
    {
        var byteIndex = index / 8;
        var bitIndexInsideByte = index % 8;

        var physicalBitIndex = isMsb
            ? 7 - bitIndexInsideByte
            : bitIndexInsideByte;

        var mask = 1 << physicalBitIndex;

        data[byteIndex] = (byte)(
            (data[byteIndex] & ~mask) |
            ((value & 1) << physicalBitIndex)
        );
    }


    public static byte[] Permute(
        byte[] input,
        int[] pBlock,
        bool isMsb,
        int startIndex)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(pBlock);

        if (input.Length * 8 != pBlock.Length)
        {
            throw new ArgumentException(
                "P-block length must be equal to input bit count."
            );
        }

        if (startIndex != 0 && startIndex != 1)
        {
            throw new ArgumentException(
                "Start index must be 0 or 1.",
                nameof(startIndex)
            );
        }

        byte[] result = new byte[input.Length];
        for (int i = 0; i < pBlock.Length; i++)
        {
            var index = pBlock[i];

            if (startIndex == 1)
            {
                index -= 1;
            }

            if (index < 0 || index >= input.Length * 8)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(pBlock),
                    $"P-block entry at position {i} is outside the input bit range."
                );
            }

            var bit = GetBit(input, index, isMsb);
            SetBit(result, i, (byte)bit, isMsb);
        }

        return result;
    }
}
