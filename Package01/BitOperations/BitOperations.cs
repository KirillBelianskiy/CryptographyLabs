namespace Package01.BitOperations;

public static class BitUtils
{
    public static byte[] Permute(
        byte[] input,
        int[] pBlock,
        bool isMsb,
        int startIndex)
    {
        if (input is null)
        {
            throw new ArgumentNullException(nameof(input), "Input cannot be null.");
        }

        if (pBlock is null)
        {
            throw new ArgumentNullException(nameof(pBlock), "P-block cannot be null.");
        }

        if (input.Length * 8 != pBlock.Length)
        {
            throw new ArgumentException(
                "P-block length must equal the input bit count.",
                nameof(pBlock));
        }

        if (startIndex != 0 && startIndex != 1)
        {
            throw new ArgumentException(
                "Start index must be 0 or 1.",
                nameof(startIndex));
        }

        byte[] result = new byte[input.Length];
        for (int i = 0; i < pBlock.Length; i++)
        {
            int index = pBlock[i];

            if (startIndex == 1)
            {
                index -= 1;
            }

            if (index < 0 || index >= input.Length * 8)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(pBlock),
                    $"P-block entry at position {i} is outside the input bit range.");
            }

            int bit = GetBit(input, index, isMsb);
            SetBit(result, i, (byte)bit, isMsb);
        }

        return result;
    }

    private static int GetBit(
        byte[] data,
        int index,
        bool isMsb)
    {
        int byteIndex = isMsb
            ? index / 8
            : data.Length - 1 - index / 8;
        int bitIndexInsideByte = index % 8;

        int physicalBitIndex = isMsb
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
        int byteIndex = isMsb
            ? index / 8
            : data.Length - 1 - index / 8;
        int bitIndexInsideByte = index % 8;

        int physicalBitIndex = isMsb
            ? 7 - bitIndexInsideByte
            : bitIndexInsideByte;

        int mask = 1 << physicalBitIndex;

        data[byteIndex] = (byte)((data[byteIndex] & ~mask) | ((value & 1) << physicalBitIndex));
    }
}
