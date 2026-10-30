using Package01.Des;

using static Package01.Demo.Tests.TestSupport;

namespace Package01.Demo.Tests;

internal static class Lab04Tests
{
    public static Task<(int Total, int Failed)> RunAsync() =>
        TestSupport.RunAsync(CreateTests());

    internal static IReadOnlyList<TestCase> CreateTests()
    {
        List<TestCase> tests = [];
        // The last three examples are the ECB blocks from FIPS 81, Appendix A.
        (string Key, string Plaintext, string Ciphertext)[] vectors =
        [
            ("133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"),
            ("0000000000000000", "0000000000000000", "8CA64DE9C1B123A7"),
            ("FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "7359B2163E4EDC58"),
            ("0123456789ABCDEF", "4E6F772069732074", "3FA40E8A984D4815"),
            ("0123456789ABCDEF", "68652074696D6520", "6A271787AB8883F9"),
            ("0123456789ABCDEF", "666F7220616C6C20", "893D51EC4B563B53")
        ];

        foreach ((string key, string plaintext, string ciphertext) in vectors)
        {
            AddTest(tests, $"DES: known vector {plaintext}/{key}", () =>
            {
                var cipher = new DesCipher();
                cipher.SetKey(Convert.FromHexString(key));
                byte[] input = Convert.FromHexString(plaintext);
                byte[] expected = Convert.FromHexString(ciphertext);
                AssertEqual(expected, cipher.EncryptBlock(input));
                AssertEqual(input, cipher.DecryptBlock(expected));
            });
        }

        AddTest(tests, "DES: first/last subkeys and first round F", () =>
        {
            byte[][] keys = new DesKeyExpansion().ExpandKey(
                Convert.FromHexString("133457799BBCDFF1"));
            Assert(keys.Length == 16, "DES must have sixteen rounds.");
            AssertEqual(Convert.FromHexString("1B02EFFC7072"), keys[0]);
            AssertEqual(Convert.FromHexString("CB3D8B0E17F5"), keys[^1]);
            var round = new DesRoundTransformation();
            AssertEqual(Convert.FromHexString("234AA9BB"), round.Transform(
                Convert.FromHexString("F0AAF0AA"), keys[0]));
        });
        AddTest(tests, "DES: parity bits do not affect round keys", () =>
        {
            byte[] key = Convert.FromHexString("133457799BBCDFF1");
            byte[] modified = key.Select(value => (byte)(value ^ 1)).ToArray();
            byte[][] expected = new DesKeyExpansion().ExpandKey(key);
            byte[][] actual = new DesKeyExpansion().ExpandKey(modified);
            for (int index = 0; index < expected.Length; index++)
            {
                AssertEqual(expected[index], actual[index]);
            }
        });
        AddTest(tests, "DES: input ownership, rekeying and validation", () =>
        {
            var cipher = new DesCipher();
            AssertThrows<InvalidOperationException>(() => cipher.EncryptBlock(new byte[8]));
            AssertThrows<ArgumentNullException>(() => cipher.SetKey(null!));
            foreach (int length in new[] { 0, 7, 9, 16 })
            {
                AssertThrows<ArgumentException>(() => cipher.SetKey(new byte[length]));
            }

            byte[] key = Convert.FromHexString("133457799BBCDFF1");
            byte[] plain = Convert.FromHexString("0123456789ABCDEF");
            cipher.SetKey(key);
            Array.Clear(key);
            AssertEqual(Convert.FromHexString("85E813540F0AB405"), cipher.EncryptBlock(plain));
            AssertEqual(Convert.FromHexString("0123456789ABCDEF"), plain);
            AssertThrows<ArgumentNullException>(() => cipher.EncryptBlock(null!));
            AssertThrows<ArgumentException>(() => cipher.DecryptBlock(new byte[9]));
            AssertThrows<ArgumentException>(() => new DesRoundTransformation().Transform([], new byte[6]));
            AssertThrows<ArgumentNullException>(() => new DesRoundTransformation().Transform(new byte[4], null!));
            cipher.SetKey(new byte[8]);
            AssertEqual(Convert.FromHexString("8CA64DE9C1B123A7"), cipher.EncryptBlock(new byte[8]));
        });
        return tests;
    }
}
