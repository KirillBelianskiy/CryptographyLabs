using Package01.Abstractions;
using Package01.Deal;
using Package01.Demo.Tests;
using Package01.Des;
using Package01.Modes;
using Package01.Padding;

using static Package01.Demo.Tests.TestSupport;

namespace Package01.Demo.Demonstrations;

internal static class CipherDemonstration
{
    internal static async Task<(int Total, int Failed)> RunAsync(
        bool useDeal, string outputDirectory)
    {
        string name = useDeal ? "DEAL" : "DES";
        Func<ISymmetricBlockCipher> createCipher = useDeal
            ? () => new DealCipher()
            : () => new DesCipher();
        byte[] key = useDeal
            ? Convert.FromHexString("000102030405060708090A0B0C0D0E0F")
            : Convert.FromHexString("133457799BBCDFF1");
        int blockSize = useDeal ? 16 : 8;
        string root = Path.Combine(Path.GetFullPath(outputDirectory), name);
        string samples = Path.Combine(root, "samples");
        await SampleFiles.CreateAsync(samples);
        List<TestCase> tests = [];

        foreach (CipherMode mode in Enum.GetValues<CipherMode>())
        {
            foreach (PaddingMode padding in Enum.GetValues<PaddingMode>())
            {
                AddAsyncTest(tests, $"{name}/{mode}/{padding}: pseudorandom arrays", async () =>
                {
                    SymmetricCipherContext context = CreateContext(
                        createCipher(), key, mode, padding);
                    var random = new Random(2026);
                    foreach (int length in new[] { 0, 1, blockSize - 1, blockSize, blockSize + 1, 257 })
                    {
                        byte[] data = new byte[length];
                        random.NextBytes(data);
                        if (data.Length > 0)
                        {
                            data[^1] = 42;
                        }

                        byte[] encrypted = await context.EncryptAsync(data);
                        AssertEqual(data, await context.DecryptAsync(encrypted));
                    }
                });
            }

            foreach (string inputPath in Directory.GetFiles(samples).Order())
            {
                string filename = Path.GetFileName(inputPath);
                AddAsyncTest(tests, $"{name}/{mode}: file {filename}", async () =>
                {
                    string directory = Path.Combine(root, mode.ToString());
                    Directory.CreateDirectory(directory);
                    string encryptedPath = Path.Combine(directory, $"{filename}.encrypted");
                    string decryptedPath = Path.Combine(directory, filename);
                    SymmetricCipherContext context = CreateContext(
                        createCipher(), key, mode, PaddingMode.Pkcs7);
                    await context.EncryptAsync(inputPath, encryptedPath);
                    await context.DecryptAsync(encryptedPath, decryptedPath);
                    AssertEqual(await File.ReadAllBytesAsync(inputPath),
                        await File.ReadAllBytesAsync(decryptedPath));
                });
            }
        }

        AddAsyncTest(tests, $"{name}: file crosses a 64 KiB buffer", async () =>
        {
            string inputPath = Path.Combine(root, "large.bin");
            string encryptedPath = Path.Combine(root, "large.bin.encrypted");
            string restoredPath = Path.Combine(root, "large-restored.bin");
            byte[] data = new byte[65537];
            new Random(1234).NextBytes(data);
            await File.WriteAllBytesAsync(inputPath, data);
            SymmetricCipherContext context = CreateContext(
                createCipher(), key, CipherMode.Ctr, PaddingMode.Pkcs7);
            byte[] expected = await context.EncryptAsync(data);
            await context.EncryptAsync(inputPath, encryptedPath);
            AssertEqual(expected, await File.ReadAllBytesAsync(encryptedPath));
            await context.DecryptAsync(encryptedPath, restoredPath);
            AssertEqual(data, await File.ReadAllBytesAsync(restoredPath));
        });
        Console.WriteLine($"Demonstration files: {root}");
        return await TestSupport.RunAsync(tests);
    }

    private static SymmetricCipherContext CreateContext(
        ISymmetricBlockCipher cipher, byte[] key,
        CipherMode mode, PaddingMode padding)
    {
        byte[]? iv = mode == CipherMode.Ecb
            ? null
            : Enumerable.Range(1, cipher.BlockSizeBytes)
                .Select(value => (byte)value).ToArray();
        byte[] delta = new byte[cipher.BlockSizeBytes];
        delta[^1] = 3;
        return mode == CipherMode.RandomDelta
            ? new SymmetricCipherContext(cipher, key, mode, padding, iv, delta)
            : new SymmetricCipherContext(cipher, key, mode, padding, iv);
    }
}
