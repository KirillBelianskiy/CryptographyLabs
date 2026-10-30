using Package01.Abstractions;
using Package01.Feistel;
using Package01.Modes;
using Package01.Padding;

using static Package01.Demo.Tests.TestSupport;

namespace Package01.Demo.Tests;

internal static class RegressionTests
{
    internal static Task<(int Total, int Failed)> RunAsync() =>
        TestSupport.RunAsync(CreateTests());

    internal static IReadOnlyList<TestCase> CreateTests()
    {
        List<TestCase> tests = [];
        AddAsyncTest(tests, "Zeros: remove tails longer than a block or buffer", async () =>
        {
            var context = new SymmetricCipherContext(
                new CopyCipher(), [1], CipherMode.Ecb, PaddingMode.Zeros);
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            try
            {
                foreach (int length in new[] { 8, 9, 32, 65536, 131073 })
                {
                    foreach (bool allZero in new[] { true, false })
                    {
                        byte[] input = new byte[length];
                        if (!allZero)
                        {
                            input[0] = 42;
                        }

                        byte[] expected = allZero ? [] : [42];
                        byte[] encrypted = await context.EncryptAsync(input);
                        AssertEqual(expected, await context.DecryptAsync(encrypted));
                        string encryptedPath = Path.Combine(directory, "encrypted");
                        string outputPath = Path.Combine(directory, "output");
                        await File.WriteAllBytesAsync(encryptedPath, encrypted);
                        await context.DecryptAsync(encryptedPath, outputPath);
                        AssertEqual(expected, await File.ReadAllBytesAsync(outputPath));
                    }
                }

                // Preserve zero bytes inside the data, across multiple buffers.
                byte[] data = new byte[131073];
                data[0] = 1;
                data[^1] = 2;
                await File.WriteAllBytesAsync(Path.Combine(directory, "input"), data);
                await context.EncryptAsync(Path.Combine(directory, "input"), Path.Combine(directory, "encrypted"));
                await context.DecryptAsync(Path.Combine(directory, "encrypted"), Path.Combine(directory, "output"));
                AssertEqual(data, await File.ReadAllBytesAsync(Path.Combine(directory, "output")));
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        });
        AddTest(tests, "Empty keys rejected by context and Feistel", () =>
        {
            AssertThrows<ArgumentException>(() => new SymmetricCipherContext(
                new CopyCipher(), [], CipherMode.Ecb, PaddingMode.Pkcs7));
            var network = new FeistelNetwork(new SingleKey(), new CopyRound());
            AssertThrows<ArgumentException>(() => network.SetKey([]));
        });
        AlgorithmAuditTests.Register(tests);
        return tests;
    }

    private sealed class CopyCipher : ISymmetricBlockCipher
    {
        public int BlockSizeBytes => 8;

        public void SetKey(byte[] key) { }

        public byte[] EncryptBlock(byte[] block) => (byte[])block.Clone();

        public byte[] DecryptBlock(byte[] block) => (byte[])block.Clone();
    }

    private sealed class SingleKey : IKeyExpansion
    {
        public byte[][] ExpandKey(byte[] key) => [key];
    }

    private sealed class CopyRound : IRoundTransformation
    {
        public byte[] Transform(byte[] inputBlock, byte[] roundKey) => inputBlock;
    }
}
