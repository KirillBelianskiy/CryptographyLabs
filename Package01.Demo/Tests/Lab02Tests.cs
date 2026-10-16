using System.Security.Cryptography;

using Package01.Abstractions;
using Package01.Feistel;

using static Package01.Demo.Tests.TestSupport;

using CipherMode = Package01.Modes.CipherMode;
using PaddingMode = Package01.Padding.PaddingMode;

namespace Package01.Demo.Tests;

internal static class Lab02Tests
{
    private const int BlockSize = 8;

    public static Task<(int Total, int Failed)> RunAsync() =>
        TestSupport.RunAsync(CreateTests());

    private static IReadOnlyList<TestCase> CreateTests()
    {
        List<TestCase> tests = [];
        RegisterContextTests(tests);
        RegisterPaddingTests(tests);
        RegisterFileTests(tests);
        return tests;
    }

    private static void RegisterContextTests(List<TestCase> tests)
    {
        // Independently calculated vectors: B=2, K1=01, K2=02, K3=03,
        // plaintext=1020304050607080, IV=00FE, delta=0003, Zeros padding.
        (CipherMode Mode, string Ciphertext)[] vectors =
        [
            (CipherMode.Ecb, "2713473367538773"),
            (CipherMode.Cbc, "DD0F4EF08B0184FA"),
            (CipherMode.Pcbc, "DD0F6EE0DB11F4FA"),
            (CipherMode.Cfb, "EDDFEE903B7104BA"),
            (CipherMode.Ofb, "EDDFCE40AB61747A"),
            (CipherMode.Ctr, "EDDF30BD55627484"),
            (CipherMode.RandomDelta, "EDDF34445162768C")
        ];

        foreach ((CipherMode mode, string ciphertext) in vectors)
        {
            AddAsyncTest(tests, $"{mode}: encrypt known message", async () =>
            {
                SymmetricCipherContext context = CreateVectorContext(mode);
                byte[] actual = await context.EncryptAsync(Convert.FromHexString("1020304050607080"));
                AssertEqual(Convert.FromHexString(ciphertext), actual);
            });
            AddAsyncTest(tests, $"{mode}: decrypt known message", async () =>
            {
                SymmetricCipherContext context = CreateVectorContext(mode);
                byte[] actual = await context.DecryptAsync(Convert.FromHexString(ciphertext));
                AssertEqual(Convert.FromHexString("1020304050607080"), actual);
            });
        }

        foreach (CipherMode mode in Enum.GetValues<CipherMode>())
        {
            foreach (PaddingMode padding in Enum.GetValues<PaddingMode>())
            {
                AddAsyncTest(tests, $"{mode}/{padding}: array round trips and input ownership", async () =>
                {
                    SymmetricCipherContext context = CreateContext(mode, padding);
                    foreach (int length in new[] { 0, 1, 7, 8, 9, 24, 32, 33, 257 })
                    {
                        byte[] input = CreateData(length);
                        byte[] original = (byte[])input.Clone();
                        byte[] encrypted = await context.EncryptAsync(input);
                        byte[] ciphertextSnapshot = (byte[])encrypted.Clone();
                        Assert(encrypted.Length % BlockSize == 0, "Ciphertext must contain complete blocks.");
                        int expectedLength = padding == PaddingMode.Zeros
                            ? (length + BlockSize - 1) / BlockSize * BlockSize
                            : (length / BlockSize + 1) * BlockSize;
                        Assert(encrypted.Length == expectedLength, $"Unexpected ciphertext length for input length {length}.");
                        AssertEqual(original, await context.DecryptAsync(encrypted), $"Round trip failed for length {length}.");
                        AssertEqual(original, input, "Encryption changed the input array.");
                        AssertEqual(ciphertextSnapshot, encrypted, "Decryption changed the ciphertext array.");
                    }
                });
            }
        }

        AddTest(tests, "Context: invalid configuration", TestContextValidation);
        AddAsyncTest(tests, "Context: invalid array arguments and ciphertext length", async () =>
        {
            SymmetricCipherContext context = CreateContext(CipherMode.Ecb, PaddingMode.Pkcs7);
            await AssertThrowsAsync<ArgumentNullException>(() => context.EncryptAsync((byte[])null!));
            await AssertThrowsAsync<ArgumentNullException>(() => context.DecryptAsync((byte[])null!));
            await AssertThrowsAsync<CryptographicException>(() => context.DecryptAsync([]));
            await AssertThrowsAsync<CryptographicException>(() => context.DecryptAsync([1]));
        });
        AddAsyncTest(tests, "Context: cancelled array operations", async () =>
        {
            using CancellationTokenSource cancellation = new();
            cancellation.Cancel();
            SymmetricCipherContext context = CreateContext(CipherMode.Ctr, PaddingMode.Pkcs7);
            await AssertThrowsAsync<OperationCanceledException>(() => context.EncryptAsync([1], cancellation.Token));
            await AssertThrowsAsync<OperationCanceledException>(() => context.DecryptAsync(new byte[BlockSize], cancellation.Token));
        });
        AddAsyncTest(tests, "Context: concurrent requests use independent mode state", async () =>
        {
            SymmetricCipherContext context = CreateVectorContext(CipherMode.Cbc);
            byte[] input = Convert.FromHexString("1020304050607080");
            Task<byte[]>[] requests = Enumerable.Range(0, 8)
                .Select(_ => context.EncryptAsync(input))
                .ToArray();
            byte[][] results = await Task.WhenAll(requests);
            foreach (byte[] result in results)
            {
                AssertEqual(Convert.FromHexString("DD0F4EF08B0184FA"), result);
            }

            AssertEqual(Convert.FromHexString("1020304050607080"), input);
        });
        AddAsyncTest(tests, "Context: IV and delta are copied", async () =>
        {
            byte[] iv = [0x00, 0xFE];
            byte[] delta = [0x00, 0x03];
            SymmetricCipherContext context = new(CreateCipher(2), [1], CipherMode.RandomDelta, PaddingMode.Zeros, iv, delta);
            Array.Fill(iv, (byte)0);
            Array.Fill(delta, (byte)0);
            AssertEqual(Convert.FromHexString("EDDF34445162768C"),
                await context.EncryptAsync(Convert.FromHexString("1020304050607080")));
        });
        AddAsyncTest(tests, "Context: invalid block cipher result", async () =>
        {
            SymmetricCipherContext context = new(new IdentityBlockCipher(returnInvalidBlock: true), [1], CipherMode.Ecb, PaddingMode.Pkcs7);
            await AssertThrowsAsync<CryptographicException>(() => context.EncryptAsync([1]));
            await AssertThrowsAsync<CryptographicException>(() => context.DecryptAsync(new byte[BlockSize]));
        });
        AddAsyncTest(tests, "RandomDelta: short-period masks repeat (known limitation)", async () =>
        {
            SymmetricCipherContext context = new(CreateCipher(2), [1], CipherMode.RandomDelta,
                PaddingMode.Zeros, [0, 0], new byte[] { 0x80, 0x00 });
            byte[] encrypted = await context.EncryptAsync(new byte[8]);
            AssertEqual(encrypted[..2], encrypted[4..6]);
            Assert(!encrypted[..2].AsSpan().SequenceEqual(encrypted[2..4]), "Consecutive masks should differ in this example.");
        });
    }

    private static void TestContextValidation()
    {
        AssertThrows<ArgumentNullException>(() => new SymmetricCipherContext(null!, [1], CipherMode.Ecb, PaddingMode.Pkcs7));
        AssertThrows<ArgumentNullException>(() => new SymmetricCipherContext(CreateCipher(), null!, CipherMode.Ecb, PaddingMode.Pkcs7));
        AssertThrows<ArgumentNullException>(() => new SymmetricCipherContext(CreateCipher(), [1], CipherMode.Ecb, PaddingMode.Pkcs7, modeParameters: null!));
        AssertThrows<ArgumentOutOfRangeException>(() => new SymmetricCipherContext(CreateCipher(), [1], (CipherMode)999, PaddingMode.Pkcs7));
        AssertThrows<ArgumentOutOfRangeException>(() => new SymmetricCipherContext(CreateCipher(), [1], CipherMode.Ecb, (PaddingMode)999));
        AssertThrows<ArgumentOutOfRangeException>(() => new SymmetricCipherContext(new IdentityBlockCipher(0), [1], CipherMode.Ecb, PaddingMode.Pkcs7));
        AssertThrows<ArgumentOutOfRangeException>(() => new SymmetricCipherContext(new IdentityBlockCipher(256), [1], CipherMode.Ecb, PaddingMode.Pkcs7));
        AssertThrows<ArgumentException>(() => new SymmetricCipherContext(CreateCipher(), [1], CipherMode.Ecb, PaddingMode.Pkcs7, new byte[BlockSize]));
        AssertThrows<ArgumentException>(() => new SymmetricCipherContext(CreateCipher(), [1], CipherMode.Cbc, PaddingMode.Pkcs7));
        AssertThrows<ArgumentException>(() => new SymmetricCipherContext(CreateCipher(), [1], CipherMode.Cbc, PaddingMode.Pkcs7, [1]));
        AssertThrows<ArgumentException>(() => new SymmetricCipherContext(CreateCipher(), [1], CipherMode.Ctr, PaddingMode.Pkcs7, new byte[BlockSize], 1));
        AssertThrows<ArgumentException>(() => new SymmetricCipherContext(CreateCipher(), [1], CipherMode.RandomDelta, PaddingMode.Pkcs7, new byte[BlockSize]));
        AssertThrows<ArgumentException>(() => new SymmetricCipherContext(CreateCipher(), [1], CipherMode.RandomDelta, PaddingMode.Pkcs7, new byte[BlockSize], 1));
        AssertThrows<ArgumentException>(() => new SymmetricCipherContext(CreateCipher(), [1], CipherMode.RandomDelta, PaddingMode.Pkcs7, new byte[BlockSize], new byte[BlockSize]));
        AssertThrows<ArgumentException>(() => new SymmetricCipherContext(CreateCipher(), [1], CipherMode.RandomDelta, PaddingMode.Pkcs7, new byte[BlockSize], new byte[] { 1 }));
    }

    private static void RegisterPaddingTests(List<TestCase> tests)
    {
        // An identity test double exposes padding through the public API,
        // without accessing internal PaddingCodec or changing the library.
        foreach (PaddingMode padding in Enum.GetValues<PaddingMode>())
        {
            AddAsyncTest(tests, $"Padding: {padding} byte format and aligned input", async () =>
            {
                SymmetricCipherContext context = new(new IdentityBlockCipher(), [1], CipherMode.Ecb, padding);
                byte[] input = [0x10, 0x20, 0x30];
                byte[] padded = await context.EncryptAsync(input);
                AssertEqual(input, padded[..input.Length]);
                Assert(padded.Length == BlockSize, "Padding must complete the block.");
                AssertPaddingBytes(padded[input.Length..], padding);
                AssertEqual(input, await context.DecryptAsync(padded));

                byte[] aligned = CreateData(BlockSize);
                byte[] paddedAligned = await context.EncryptAsync(aligned);
                int expectedLength = padding == PaddingMode.Zeros ? BlockSize : 2 * BlockSize;
                Assert(paddedAligned.Length == expectedLength, "Unexpected padding for aligned input.");
                AssertEqual(aligned, paddedAligned[..BlockSize]);
                AssertPaddingBytes(paddedAligned[BlockSize..], padding);
                AssertEqual(aligned, await context.DecryptAsync(paddedAligned));

                byte[] empty = await context.EncryptAsync([]);
                Assert(empty.Length == (padding == PaddingMode.Zeros ? 0 : BlockSize), "Unexpected padding for empty input.");
                AssertPaddingBytes(empty, padding);
                AssertEqual([], await context.DecryptAsync(empty));

                byte[] singlePaddingByte = await context.EncryptAsync(CreateData(BlockSize - 1));
                Assert(singlePaddingByte[^1] == (padding == PaddingMode.Zeros ? 0 : 1), "Invalid one-byte padding.");
            });
        }

        foreach (PaddingMode padding in new[] { PaddingMode.AnsiX923, PaddingMode.Pkcs7, PaddingMode.Iso10126 })
        {
            AddAsyncTest(tests, $"Padding: {padding} rejects invalid length", async () =>
            {
                SymmetricCipherContext context = new(new IdentityBlockCipher(), [1], CipherMode.Ecb, padding);
                await AssertThrowsAsync<CryptographicException>(() => context.DecryptAsync(new byte[BlockSize]));
                byte[] invalid = CreateData(BlockSize);
                invalid[^1] = BlockSize + 1;
                await AssertThrowsAsync<CryptographicException>(() => context.DecryptAsync(invalid));
            });
        }

        AddAsyncTest(tests, "Padding: PKCS7 rejects inconsistent padding bytes", async () =>
        {
            SymmetricCipherContext context = new(new IdentityBlockCipher(), [1], CipherMode.Ecb, PaddingMode.Pkcs7);
            await AssertThrowsAsync<CryptographicException>(() => context.DecryptAsync([0x10, 0x20, 0x30, 5, 5, 4, 5, 5]));
        });
        AddAsyncTest(tests, "Padding: ANSI X.923 rejects nonzero padding bytes", async () =>
        {
            SymmetricCipherContext context = new(new IdentityBlockCipher(), [1], CipherMode.Ecb, PaddingMode.AnsiX923);
            await AssertThrowsAsync<CryptographicException>(() => context.DecryptAsync([0x10, 0x20, 0x30, 0, 1, 0, 0, 5]));
        });
        AddAsyncTest(tests, "Padding: Zeros loses original trailing zeros (known limitation)", async () =>
        {
            SymmetricCipherContext context = CreateContext(CipherMode.Cbc, PaddingMode.Zeros);
            byte[] input = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0];
            AssertEqual(input[..^1], await context.DecryptAsync(await context.EncryptAsync(input)));
        });
    }

    private static void AssertPaddingBytes(byte[] paddingBytes, PaddingMode padding)
    {
        if (padding == PaddingMode.Zeros)
        {
            Assert(paddingBytes.All(value => value == 0), "Zeros padding must contain only zero bytes.");
            return;
        }

        Assert(paddingBytes.Length > 0, "A padding block is required.");
        Assert(paddingBytes[^1] == paddingBytes.Length, "The last byte must store the padding length.");
        if (padding == PaddingMode.Pkcs7)
        {
            Assert(paddingBytes.All(value => value == paddingBytes.Length), "PKCS7 padding bytes must equal its length.");
        }
        else if (padding == PaddingMode.AnsiX923)
        {
            Assert(paddingBytes[..^1].All(value => value == 0), "ANSI X.923 padding bytes before the length must be zero.");
        }
        // ISO 10126 random bytes have no fixed expected contents.
    }

    private static void RegisterFileTests(List<TestCase> tests)
    {
        foreach (CipherMode mode in Enum.GetValues<CipherMode>())
        {
            foreach (PaddingMode padding in Enum.GetValues<PaddingMode>())
            {
                AddAsyncTest(tests, $"Files: {mode}/{padding}, empty, aligned and multiple buffers", () =>
                    WithTemporaryDirectory(async directory =>
                    {
                        SymmetricCipherContext context = CreateContext(mode, padding);
                        string inputPath = Path.Combine(directory, "input.bin");
                        string encryptedPath = Path.Combine(directory, "encrypted.bin");
                        string decryptedPath = Path.Combine(directory, "decrypted.bin");

                        foreach (int length in new[] { 0, BlockSize, 2 * 64 * 1024 + 13 })
                        {
                            byte[] input = CreateData(length);
                            await File.WriteAllBytesAsync(inputPath, input);
                            await context.EncryptAsync(inputPath, encryptedPath);
                            byte[] encrypted = await File.ReadAllBytesAsync(encryptedPath);
                            if (padding != PaddingMode.Iso10126)
                            {
                                AssertEqual(await context.EncryptAsync(input), encrypted,
                                    $"File and array encryption differ for length {length}.");
                            }

                            AssertEqual(input, await context.DecryptAsync(encrypted));
                            await context.DecryptAsync(encryptedPath, decryptedPath);
                            AssertEqual(input, await File.ReadAllBytesAsync(decryptedPath));
                            AssertEqual(input, await File.ReadAllBytesAsync(inputPath), "The input file was modified.");
                            Assert(Directory.GetFiles(directory).Length == 3, "A temporary file was left after success.");
                        }
                    }));
            }
        }

        AddAsyncTest(tests, "Files: same input and output path", () =>
            WithTemporaryDirectory(async directory =>
            {
                string path = Path.Combine(directory, "data.bin");
                byte[] input = CreateData(257);
                SymmetricCipherContext context = CreateContext(CipherMode.Cbc, PaddingMode.Pkcs7);
                await File.WriteAllBytesAsync(path, input);
                await context.EncryptAsync(path, path);
                AssertEqual(await context.EncryptAsync(input), await File.ReadAllBytesAsync(path));
                await context.DecryptAsync(path, path);
                AssertEqual(input, await File.ReadAllBytesAsync(path));
                Assert(Directory.GetFiles(directory).Length == 1, "A temporary file was left after replacement.");
            }));
        AddAsyncTest(tests, "Files: invalid ciphertext preserves existing output", () =>
            WithTemporaryDirectory(async directory =>
            {
                string inputPath = Path.Combine(directory, "invalid.bin");
                string outputPath = Path.Combine(directory, "output.bin");
                byte[] originalOutput = [0xDE, 0xAD, 0xBE, 0xEF];
                SymmetricCipherContext context = new(new IdentityBlockCipher(), [1], CipherMode.Ecb, PaddingMode.Pkcs7);
                foreach (byte[] invalid in new[] { new byte[1], new byte[2 * 64 * 1024 + BlockSize] })
                {
                    await File.WriteAllBytesAsync(inputPath, invalid);
                    await File.WriteAllBytesAsync(outputPath, originalOutput);
                    await AssertThrowsAsync<CryptographicException>(() => context.DecryptAsync(inputPath, outputPath));
                    AssertEqual(originalOutput, await File.ReadAllBytesAsync(outputPath));
                    Assert(Directory.GetFiles(directory).Length == 2, "A temporary file was left after failure.");
                }
            }));
        AddAsyncTest(tests, "Files: cancellation preserves existing output", () =>
            WithTemporaryDirectory(async directory =>
            {
                string inputPath = Path.Combine(directory, "input.bin");
                string outputPath = Path.Combine(directory, "output.bin");
                byte[] originalOutput = [0xDE, 0xAD];
                await File.WriteAllBytesAsync(inputPath, CreateData(257));
                await File.WriteAllBytesAsync(outputPath, originalOutput);
                using CancellationTokenSource cancellation = new();
                cancellation.Cancel();
                SymmetricCipherContext context = CreateContext(CipherMode.Cbc, PaddingMode.Pkcs7);
                await AssertThrowsAsync<OperationCanceledException>(() =>
                    context.EncryptAsync(inputPath, outputPath, cancellation.Token));
                AssertEqual(originalOutput, await File.ReadAllBytesAsync(outputPath));
                Assert(Directory.GetFiles(directory).Length == 2, "A temporary file was left after cancellation.");
            }));
        AddAsyncTest(tests, "Files: invalid paths", () =>
            WithTemporaryDirectory(async directory =>
            {
                SymmetricCipherContext context = CreateContext(CipherMode.Ecb, PaddingMode.Pkcs7);
                string inputPath = Path.Combine(directory, "input.bin");
                string outputPath = Path.Combine(directory, "output.bin");
                await File.WriteAllBytesAsync(inputPath, [1]);
                await AssertThrowsAsync<ArgumentNullException>(() => context.EncryptAsync(null!, outputPath));
                await AssertThrowsAsync<ArgumentException>(() => context.EncryptAsync(" ", outputPath));
                await AssertThrowsAsync<ArgumentException>(() => context.DecryptAsync(inputPath, ""));
                await AssertThrowsAsync<FileNotFoundException>(() =>
                    context.EncryptAsync(Path.Combine(directory, "missing.bin"), outputPath));
            }));
    }

    private static SymmetricCipherContext CreateContext(CipherMode mode, PaddingMode padding)
    {
        byte[]? iv = mode == CipherMode.Ecb ? null : CreateData(BlockSize);
        return mode == CipherMode.RandomDelta
            ? new SymmetricCipherContext(CreateCipher(), [1], mode, padding, iv,
                new byte[] { 0, 0, 0, 0, 0, 0, 0, 3 })
            : new SymmetricCipherContext(CreateCipher(), [1], mode, padding, iv);
    }

    private static SymmetricCipherContext CreateVectorContext(CipherMode mode)
    {
        byte[]? iv = mode == CipherMode.Ecb ? null : [0x00, 0xFE];
        return mode == CipherMode.RandomDelta
            ? new SymmetricCipherContext(CreateCipher(2), [1], mode, PaddingMode.Zeros, iv,
                new byte[] { 0x00, 0x03 })
            : new SymmetricCipherContext(CreateCipher(2), [1], mode, PaddingMode.Zeros, iv);
    }

    private sealed class IdentityBlockCipher(int blockSizeBytes = BlockSize, bool returnInvalidBlock = false) : ISymmetricBlockCipher
    {
        public int BlockSizeBytes { get; } = blockSizeBytes;

        public void SetKey(byte[] key) => ArgumentNullException.ThrowIfNull(key);

        public byte[] EncryptBlock(byte[] block) => returnInvalidBlock ? block[..^1] : (byte[])block.Clone();

        public byte[] DecryptBlock(byte[] block) => EncryptBlock(block);
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

    private static async Task WithTemporaryDirectory(Func<string, Task> test)
    {
        string directory = Path.Combine(Path.GetTempPath(), $"CryptographyLabs.Tests.{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            await test(directory);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
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
}
