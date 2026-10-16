using System.Numerics;

using Package01.Abstractions;
using Package01.Des;
using Package01.Modes;
using Package01.Padding;

using static Package01.Demo.Tests.TestSupport;

namespace Package01.Demo.Tests;

internal static class AlgorithmAuditTests
{
    internal static void Register(List<TestCase> tests)
    {
        foreach (CipherMode mode in Enum.GetValues<CipherMode>())
        {
            AddAsyncTest(tests, $"Audit: {mode}, formula and in-place cipher", async () =>
            {
                byte[] iv = [0xFF, 0xFF, 0xFD];
                byte[] delta = [0x80, 0, 3];
                byte[] data = CreateData(3 * 160);
                SymmetricCipherContext context = CreateContext(
                    new AdditionCipher(3, inPlace: true), mode,
                    PaddingMode.Zeros, iv, delta);
                byte[] expected = ReferenceEncrypt(data, mode, iv, delta);
                AssertEqual(expected, await context.EncryptAsync(data),
                    $"{mode}: encryption differs from the formula.");
                AssertEqual(data, await context.DecryptAsync(expected),
                    $"{mode}: decryption with an in-place cipher failed.");
            });
        }

        foreach ((CipherMode mode, string ciphertext) in new[]
        {
            (CipherMode.Cbc, "E5C7CDDE872BF27C43E934008C389C0F683788499A7C05F6"),
            (CipherMode.Cfb, "F3096249C7F46E51A69E839B1A92F78403467133898EA622")
        })
        {
            AddAsyncTest(tests, $"Audit: DES/{mode}, NIST FIPS 81", async () =>
            {
                var context = new SymmetricCipherContext(
                    new DesCipher(), Convert.FromHexString("0123456789ABCDEF"),
                    mode, PaddingMode.Zeros,
                    Convert.FromHexString("1234567890ABCDEF"));
                byte[] input = Convert.FromHexString(
                    "4E6F77206973207468652074696D6520666F7220616C6C20");
                byte[] expected = Convert.FromHexString(ciphertext);
                AssertEqual(expected, await context.EncryptAsync(input));
                AssertEqual(input, await context.DecryptAsync(expected));
            });
        }

        foreach (PaddingMode padding in Enum.GetValues<PaddingMode>())
        {
            AddAsyncTest(tests, $"Audit: {padding}, block size 255", async () =>
            {
                var context = new SymmetricCipherContext(
                    new AdditionCipher(255, inPlace: false), [13],
                    CipherMode.Ecb, padding);
                foreach (int length in new[] { 0, 1, 254, 255, 256, 509, 510 })
                {
                    byte[] data = CreateData(length);
                    byte[] encrypted = await context.EncryptAsync(data);
                    AssertEqual(data, await context.DecryptAsync(encrypted));
                }
            });
        }

        AddAsyncTest(tests, "Audit: Zeros allows blocks larger than 255", async () =>
        {
            foreach (int blockSize in new[] { 256, 257, 1024 })
            {
                var context = new SymmetricCipherContext(
                    new AdditionCipher(blockSize, inPlace: false), [13],
                    CipherMode.Ecb, PaddingMode.Zeros);
                foreach (int length in new[] { 0, 1, blockSize, blockSize + 1 })
                {
                    byte[] data = CreateData(length);
                    AssertEqual(data, await context.DecryptAsync(
                        await context.EncryptAsync(data)));
                }

                AssertThrows<ArgumentOutOfRangeException>(() =>
                    new SymmetricCipherContext(
                        new AdditionCipher(blockSize, inPlace: false), [13],
                        CipherMode.Ecb, PaddingMode.Pkcs7));
            }
        });

        AddAsyncTest(tests, "Audit: in-place PCBC across file buffers", async () =>
        {
            string directory = Path.Combine(
                Path.GetTempPath(), $"CryptoAudit.{Guid.NewGuid():N}");
            Directory.CreateDirectory(directory);
            try
            {
                foreach (int blockSize in new[] { 3, 256, 257 })
                {
                    byte[] iv = Enumerable.Repeat((byte)17, blockSize).ToArray();
                    var context = new SymmetricCipherContext(
                        new AdditionCipher(blockSize, inPlace: true), [13],
                        CipherMode.Pcbc, PaddingMode.Zeros, iv);
                    byte[] data = CreateData(131073);
                    string inputPath = Path.Combine(directory, "input");
                    string encryptedPath = Path.Combine(directory, "encrypted");
                    string outputPath = Path.Combine(directory, "output");
                    await File.WriteAllBytesAsync(inputPath, data);
                    await context.EncryptAsync(inputPath, encryptedPath);
                    AssertEqual(await context.EncryptAsync(data),
                        await File.ReadAllBytesAsync(encryptedPath));
                    await context.DecryptAsync(encryptedPath, outputPath);
                    AssertEqual(data, await File.ReadAllBytesAsync(outputPath));
                }
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        });

        AddTest(tests, "Audit: DES complementation and key snapshot", () =>
        {
            var random = new Random(109);
            for (int iteration = 0; iteration < 32; iteration++)
            {
                byte[] key = new byte[8];
                byte[] input = new byte[8];
                random.NextBytes(key);
                random.NextBytes(input);
                var cipher = new DesCipher();
                var complementCipher = new DesCipher();
                cipher.SetKey(key);
                complementCipher.SetKey(Complement(key));
                byte[] encrypted = cipher.EncryptBlock(input);
                AssertEqual(Complement(encrypted),
                    complementCipher.EncryptBlock(Complement(input)));
                AssertEqual(input, cipher.DecryptBlock(encrypted));
                AssertThrows<ArgumentException>(() => cipher.SetKey([1]));
                AssertEqual(encrypted, cipher.EncryptBlock(input));
            }
        });
    }

    private static SymmetricCipherContext CreateContext(
        ISymmetricBlockCipher cipher, CipherMode mode,
        PaddingMode padding, byte[] iv, byte[] delta)
    {
        if (mode == CipherMode.RandomDelta)
        {
            return new SymmetricCipherContext(
                cipher, [13], mode, padding, iv, delta);
        }

        return new SymmetricCipherContext(
            cipher, [13], mode, padding, mode == CipherMode.Ecb ? null : iv);
    }

    // This oracle uses the mathematical block relations. BigInteger counters
    // are deliberately different from the byte-wise implementation in production.
    private static byte[] ReferenceEncrypt(
        byte[] data, CipherMode mode, byte[] iv, byte[] delta)
    {
        int size = iv.Length;
        byte[] output = new byte[data.Length];
        byte[] previousPlain = new byte[size];
        byte[] previousCipher = (byte[])iv.Clone();
        byte[] gamma = (byte[])iv.Clone();
        var initial = new BigInteger(iv, isUnsigned: true, isBigEndian: true);
        BigInteger step = mode == CipherMode.Ctr
            ? BigInteger.One
            : new BigInteger(delta, isUnsigned: true, isBigEndian: true);
        BigInteger modulus = BigInteger.One << (size * 8);
        for (int index = 0; index < data.Length / size; index++)
        {
            byte[] plain = data.AsSpan(index * size, size).ToArray();
            byte[] encrypted;
            switch (mode)
            {
                case CipherMode.Ecb:
                    encrypted = Encrypt(plain);
                    break;
                case CipherMode.Cbc:
                    encrypted = Encrypt(Xor(plain, previousCipher));
                    break;
                case CipherMode.Pcbc:
                    encrypted = Encrypt(Xor(Xor(plain, previousPlain), previousCipher));
                    break;
                case CipherMode.Cfb:
                    encrypted = Xor(plain, Encrypt(previousCipher));
                    break;
                case CipherMode.Ofb:
                    gamma = Encrypt(gamma);
                    encrypted = Xor(plain, gamma);
                    break;
                case CipherMode.Ctr:
                case CipherMode.RandomDelta:
                    BigInteger counter = (initial + index * step) % modulus;
                    byte[] packed = counter.ToByteArray(isUnsigned: true, isBigEndian: true);
                    byte[] state = new byte[size];
                    packed.CopyTo(state, size - packed.Length);
                    encrypted = Xor(plain, Encrypt(state));
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(mode));
            }

            encrypted.CopyTo(output, index * size);
            previousPlain = plain;
            previousCipher = encrypted;
        }

        return output;
    }

    private static byte[] Encrypt(byte[] input) =>
        input.Select(value => (byte)((value + 13) % 256)).ToArray();

    private static byte[] Xor(byte[] left, byte[] right) =>
        left.Zip(right, (a, b) => (byte)(a ^ b)).ToArray();

    private static byte[] Complement(byte[] data) =>
        data.Select(value => (byte)(value ^ 0xFF)).ToArray();

    private static byte[] CreateData(int length)
    {
        byte[] data = new byte[length];
        new Random(730).NextBytes(data);
        if (length > 0)
        {
            data[^1] = 42;
        }

        return data;
    }

    private sealed class AdditionCipher(int size, bool inPlace) : ISymmetricBlockCipher
    {
        public int BlockSizeBytes => size;

        public void SetKey(byte[] key) { }

        public byte[] EncryptBlock(byte[] block) => Apply(block, 13);

        public byte[] DecryptBlock(byte[] block) => Apply(block, -13);

        private byte[] Apply(byte[] block, int delta)
        {
            byte[] result = inPlace ? block : (byte[])block.Clone();
            for (int index = 0; index < result.Length; index++)
            {
                result[index] = (byte)((result[index] + delta + 256) % 256);
            }

            return result;
        }
    }
}
