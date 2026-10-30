using Package01.BitOperations;

using static Package01.Demo.Tests.TestSupport;

namespace Package01.Demo.Tests;

internal static class Lab01Tests
{
    public static Task<(int Total, int Failed)> RunAsync() =>
        TestSupport.RunAsync(CreateTests());

    internal static IReadOnlyList<TestCase> CreateTests()
    {
        List<TestCase> tests = [];
        RegisterBitTests(tests);
        return tests;
    }

    private static void RegisterBitTests(List<TestCase> tests)
    {
        int[] reverse = [7, 6, 5, 4, 3, 2, 1, 0];
        int[] swapFirstBits = [1, 0, 2, 3, 4, 5, 6, 7];
        int[] globalSwap = Enumerable.Range(0, 16).ToArray();
        (globalSwap[0], globalSwap[1]) = (globalSwap[1], globalSwap[0]);
        int[] crossByteSwap = Enumerable.Range(0, 16).ToArray();
        (crossByteSwap[7], crossByteSwap[8]) = (crossByteSwap[8], crossByteSwap[7]);

        AddTest(tests, "Bits: reverse B2 in MSB order", () =>
            AssertEqual([0x4D], BitUtils.Permute([0xB2], reverse, true, 0)));
        AddTest(tests, "Bits: reverse B2 in LSB order with one-based indices", () =>
            AssertEqual([0x4D], BitUtils.Permute([0xB2], [8, 7, 6, 5, 4, 3, 2, 1], false, 1)));
        AddTest(tests, "Bits: swap the two most significant bits", () =>
            AssertEqual([0x72], BitUtils.Permute([0xB2], swapFirstBits, true, 0)));
        AddTest(tests, "Bits: swap the two least significant bits", () =>
            AssertEqual([0xB1], BitUtils.Permute([0xB2], swapFirstBits, false, 0)));
        AddTest(tests, "Bits: global MSB indexing starts in the first byte", () =>
            AssertEqual([0x40, 0x01], BitUtils.Permute([0x80, 0x01], globalSwap, true, 0)));
        AddTest(tests, "Bits: global LSB indexing starts in the last byte", () =>
            AssertEqual([0x80, 0x02], BitUtils.Permute([0x80, 0x01], globalSwap, false, 0)));
        AddTest(tests, "Bits: move a bit across a byte boundary in MSB order", () =>
            AssertEqual([0x00, 0x80], BitUtils.Permute([0x01, 0x00], crossByteSwap, true, 0)));
        AddTest(tests, "Bits: move a bit across a byte boundary in LSB order", () =>
            AssertEqual([0x00, 0x80], BitUtils.Permute([0x01, 0x00], crossByteSwap, false, 0)));
        AddTest(tests, "Bits: empty input", () =>
            AssertEqual([], BitUtils.Permute([], [], true, 0)));
        AddTest(tests, "Bits: inverse permutation and unchanged input", TestInversePermutation);
        AddTest(tests, "Bits: invalid arguments", TestBitValidation);
    }

    private static void TestInversePermutation()
    {
        byte[] input = [0xB2, 0x69, 0xE5];
        int[] permutation = Enumerable.Range(0, 24).Select(index => (index * 5 + 7) % 24).ToArray();
        int[] inverse = new int[permutation.Length];
        for (int index = 0; index < permutation.Length; index++)
        {
            inverse[permutation[index]] = index;
        }

        foreach (bool isMsb in new[] { true, false })
        {
            foreach (int startIndex in new[] { 0, 1 })
            {
                int[] table = permutation.Select(index => index + startIndex).ToArray();
                int[] inverseTable = inverse.Select(index => index + startIndex).ToArray();
                byte[] permuted = BitUtils.Permute(input, table, isMsb, startIndex);
                AssertEqual(input, BitUtils.Permute(permuted, inverseTable, isMsb, startIndex));
            }
        }

        AssertEqual([0xB2, 0x69, 0xE5], input);
    }

    private static void TestBitValidation()
    {
        int[] identity = Enumerable.Range(0, 8).ToArray();
        AssertThrows<ArgumentNullException>(() => BitUtils.Permute(null!, identity, true, 0));
        AssertThrows<ArgumentNullException>(() => BitUtils.Permute([0], null!, true, 0));
        AssertEqual([0x80], BitUtils.Permute([0x80], [0], true, 0));
        AssertEqual([0xC0], BitUtils.Permute([0x80], [0, 0], true, 0));
        AssertEqual([0xFF, 0x80], BitUtils.Permute(
            [0x80], new int[9], true, 0));
        AssertThrows<ArgumentOutOfRangeException>(() =>
            BitUtils.Permute([0], [int.MinValue], true, 1));
        AssertThrows<ArgumentException>(() => BitUtils.Permute([0], identity, true, -1));
        AssertThrows<ArgumentException>(() => BitUtils.Permute([0], identity, true, 2));
        AssertThrows<ArgumentOutOfRangeException>(() =>
            BitUtils.Permute([0], [-1, 1, 2, 3, 4, 5, 6, 7], true, 0));
        AssertThrows<ArgumentOutOfRangeException>(() =>
            BitUtils.Permute([0], [8, 1, 2, 3, 4, 5, 6, 7], false, 0));
        AssertThrows<ArgumentOutOfRangeException>(() => BitUtils.Permute([0], identity, true, 1));
    }

}
