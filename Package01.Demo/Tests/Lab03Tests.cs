using Package01.Abstractions;
using Package01.Feistel;

using static Package01.Demo.Tests.TestSupport;

namespace Package01.Demo.Tests;

internal static class Lab03Tests
{
    private const int BlockSize = 8;

    public static Task<(int Total, int Failed)> RunAsync() =>
        TestSupport.RunAsync(CreateTests());

    private static IReadOnlyList<TestCase> CreateTests()
    {
        List<TestCase> tests = [];
        RegisterFeistelTests(tests);
        return tests;
    }

    private static void RegisterFeistelTests(List<TestCase> tests)
    {
        (string Plaintext, string Ciphertext)[] vectors =
        [
            ("1020", "2713"),
            ("0000", "0703"),
            ("FFFF", "FEFE"),
            ("FF00", "FD00"),
            ("00FF", "00FD")
        ];

        foreach ((string plaintext, string ciphertext) in vectors)
        {
            AddTest(tests, $"Feistel: encrypt known block {plaintext}", () =>
            {
                FeistelNetwork cipher = CreateCipher(2);
                cipher.SetKey([1]);
                AssertEqual(Convert.FromHexString(ciphertext), cipher.EncryptBlock(Convert.FromHexString(plaintext)));
            });
            AddTest(tests, $"Feistel: decrypt known block {ciphertext}", () =>
            {
                FeistelNetwork cipher = CreateCipher(2);
                cipher.SetKey([1]);
                AssertEqual(Convert.FromHexString(plaintext), cipher.DecryptBlock(Convert.FromHexString(ciphertext)));
            });
        }

        AddTest(tests, "Feistel: different block sizes and round counts", TestFeistelRoundTrips);
        AddTest(tests, "Feistel: noninvertible constant round function", () =>
        {
            FeistelNetwork cipher = new(new FixedKeyExpansion([[1], [2], [3]]), new ConstantRoundTransformation(4));
            cipher.SetKey([1]);
            byte[] input = CreateData(BlockSize);
            AssertEqual(input, cipher.DecryptBlock(cipher.EncryptBlock(input)));
        });
        AddTest(tests, "Feistel: round keys are copied", () =>
        {
            byte[][] roundKeys = [[1], [2], [3]];
            FeistelNetwork cipher = new(new FixedKeyExpansion(roundKeys), new AdditionRoundTransformation(), 2);
            cipher.SetKey([1]);
            roundKeys[0][0] = 0xFF;
            roundKeys[1] = [0xAA];
            AssertEqual([0x27, 0x13], cipher.EncryptBlock([0x10, 0x20]));
        });
        AddTest(tests, "Feistel: round function cannot modify stored halves or keys", () =>
        {
            FeistelNetwork cipher = new(new FixedKeyExpansion([[1], [2], [3]]), new MutatingRoundTransformation(), 2);
            cipher.SetKey([1]);
            byte[] input = [0x10, 0x20];
            AssertEqual([0x27, 0x13], cipher.EncryptBlock(input));
            AssertEqual([0x27, 0x13], cipher.EncryptBlock(input));
            AssertEqual([0x10, 0x20], input);
        });
        AddTest(tests, "Feistel: invalid arguments and dependency results", TestFeistelValidation);
    }

    private static void TestFeistelRoundTrips()
    {
        foreach (int blockSize in new[] { 2, 8, 16 })
        {
            foreach (int roundCount in new[] { 1, 2, 3, 16 })
            {
                byte[][] keys = Enumerable.Range(1, roundCount)
                    .Select(index => new byte[] { (byte)index, (byte)(index + 1) })
                    .ToArray();
                FeistelNetwork cipher = new(new FixedKeyExpansion(keys), new AdditionRoundTransformation(), blockSize);
                cipher.SetKey([1]);
                byte[] input = CreateData(blockSize);
                byte[] snapshot = (byte[])input.Clone();
                byte[] encrypted = cipher.EncryptBlock(input);
                AssertEqual(snapshot, cipher.DecryptBlock(encrypted));
                AssertEqual(snapshot, input);
                Assert(!ReferenceEquals(input, encrypted), "The cipher must return a separate array.");
            }
        }
    }

    private static void TestFeistelValidation()
    {
        AssertThrows<ArgumentNullException>(() => new FeistelNetwork(null!, new AdditionRoundTransformation()));
        AssertThrows<ArgumentNullException>(() => new FeistelNetwork(new FixedKeyExpansion([[1]]), null!));
        AssertThrows<ArgumentOutOfRangeException>(() => CreateCipher(0));
        AssertThrows<ArgumentOutOfRangeException>(() => CreateCipher(3));

        FeistelNetwork cipher = CreateCipher(2);
        AssertThrows<InvalidOperationException>(() => cipher.EncryptBlock([0, 0]));
        AssertThrows<InvalidOperationException>(() => cipher.DecryptBlock([0, 0]));
        AssertThrows<ArgumentNullException>(() => cipher.SetKey(null!));
        cipher.SetKey([1]);
        AssertThrows<ArgumentNullException>(() => cipher.EncryptBlock(null!));
        AssertThrows<ArgumentException>(() => cipher.EncryptBlock([0]));
        AssertThrows<ArgumentException>(() => cipher.DecryptBlock([0, 0, 0]));

        foreach (byte[][] invalidKeys in new byte[][][] { null!, [], [null!], [[]] })
        {
            FeistelNetwork invalid = new(new FixedKeyExpansion(invalidKeys), new AdditionRoundTransformation(), 2);
            AssertThrows<InvalidOperationException>(() => invalid.SetKey([1]));
        }

        FeistelNetwork invalidRound = new(new FixedKeyExpansion([[1]]), new ConstantRoundTransformation(2), 2);
        invalidRound.SetKey([1]);
        AssertThrows<InvalidOperationException>(() => invalidRound.EncryptBlock([0, 0]));
    }

    private sealed class MutatingRoundTransformation : IRoundTransformation
    {
        private readonly AdditionRoundTransformation _inner = new();

        public byte[] Transform(byte[] inputBlock, byte[] roundKey)
        {
            byte[] result = _inner.Transform(inputBlock, roundKey);
            Array.Fill(inputBlock, (byte)0);
            Array.Fill(roundKey, (byte)0);
            return result;
        }
    }

    private static FeistelNetwork CreateCipher(int blockSize = BlockSize) =>
        new(new FixedKeyExpansion([[1], [2], [3]]), new AdditionRoundTransformation(), blockSize);

    private static byte[] CreateData(int length)
    {
        byte[] data = new byte[length];
        for (int index = 0; index < data.Length; index++)
        {
            data[index] = (byte)(index * 73 + 19);
        }

        // Zeros round trips need a nonzero final data byte.
        if (data.Length > 0)
        {
            data[^1] = 0x7F;
        }

        return data;
    }


    private sealed class FixedKeyExpansion(byte[][] roundKeys) : IKeyExpansion
    {
        public byte[][] ExpandKey(byte[] key) => roundKeys;
    }

    private sealed class AdditionRoundTransformation : IRoundTransformation
    {
        public byte[] Transform(byte[] inputBlock, byte[] roundKey)
        {
            byte[] result = new byte[inputBlock.Length];
            for (int i = 0; i < result.Length; i++)
            {
                result[i] = (byte)(inputBlock[i] + roundKey[i % roundKey.Length]);
            }

            return result;
        }
    }

    private sealed class ConstantRoundTransformation(int outputLength) : IRoundTransformation
    {
        public byte[] Transform(byte[] inputBlock, byte[] roundKey) =>
            Enumerable.Repeat((byte)0xAA, outputLength).ToArray();
    }
}
