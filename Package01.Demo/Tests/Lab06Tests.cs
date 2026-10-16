using Package01.Deal;

using static Package01.Demo.Tests.TestSupport;

namespace Package01.Demo.Tests;

internal static class Lab06Tests
{
    public static Task<(int Total, int Failed)> RunAsync()
    {
        List<TestCase> tests = [];
        // Regression vectors calculated separately with integer/bit DES and
        // alternating A/B updates, without the reusable Feistel class.
        (string Key, string Plaintext, string Ciphertext, string[] RoundKeys)[] vectors =
        [
            ("000102030405060708090A0B0C0D0E0F",
                "000102030405060708090A0B0C0D0E0F", "35A63657D179538CA9DE13BE8B9E8548",
                ["3260266C2CF202E2", "79CF70CD1DAC09A5", "4D29ED01607E2A58", "70DAB168C2F349B8", "6F02D327070A6578", "91DCCE2439827D3E"]),
            ("00000000000000000000000000000000",
                "00000000000000000000000000000000", "02CC32F106F4328737C38426079AC9DE",
                ["D5D44FF720683D0D", "5661E9804FE87B77", "FFE7DED5509A4666", "3DF3CC80990AC660", "E6C81E4AD91192E7", "EBA67119BBF0AF22"]),
            ("000102030405060708090A0B0C0D0E0F1011121314151617",
                "000102030405060708090A0B0C0D0E0F", "F8C3C3A1969757657863117944EF2979",
                ["3260266C2CF202E2", "79CF70CD1DAC09A5", "B218E9CA8B9251F2", "9DD80B7DD35D25CA", "780F554A37CDC165", "D594BAD2C4216A8D"]),
            ("000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000", "DEB301210266750E265B0482A5D2181D",
                ["D5D44FF720683D0D", "5661E9804FE87B77", "9AED30BB219FDA91", "C1893DE0617F34BC", "B0F57AA8F6BE48FC", "0D80AE8E1D5C48CB"]),
            ("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                "000102030405060708090A0B0C0D0E0F", "1E39D733E214CE2875E4BF7C21C89EE6",
                ["3260266C2CF202E2", "79CF70CD1DAC09A5", "B218E9CA8B9251F2", "4512CAB9AF4AAE12", "95C6EC297D5572C4", "2653231022A9BE71", "D614571DEEDC34B1", "B9A25B74A14F709D"]),
            ("0000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000", "614F67C16AA5EC51F0137A90D2268B14",
                ["D5D44FF720683D0D", "5661E9804FE87B77", "9AED30BB219FDA91", "8728C0B50AFC3749", "10B13C30648C2418", "F6DEB8BA35E0379F", "0D5F3747A91D578D", "571B853D27DD7BF3"])
        ];

        foreach ((string key, string plaintext, string ciphertext, string[] roundKeys) in vectors)
        {
            AddTest(tests, $"DEAL-{key.Length * 4}: reference block {plaintext}", () =>
            {
                var cipher = new DealCipher();
                cipher.SetKey(Convert.FromHexString(key));
                byte[] input = Convert.FromHexString(plaintext);
                byte[] expected = Convert.FromHexString(ciphertext);
                AssertEqual(expected, cipher.EncryptBlock(input));
                AssertEqual(input, cipher.DecryptBlock(expected));
            });
            AddTest(tests, $"DEAL-{key.Length * 4}: reference key schedule {key}", () =>
            {
                byte[][] actual = new DealKeyExpansion().ExpandKey(Convert.FromHexString(key));
                Assert(actual.Length == roundKeys.Length, "Incorrect DEAL round count.");
                for (int index = 0; index < actual.Length; index++)
                {
                    AssertEqual(Convert.FromHexString(roundKeys[index]), actual[index]);
                }
            });
        }

        AddTest(tests, "DEAL: DES adapter uses full DES, including IP/FP", () =>
        {
            var adapter = new DesRoundAdapter();
            AssertEqual(Convert.FromHexString("85E813540F0AB405"), adapter.Transform(
                Convert.FromHexString("0123456789ABCDEF"),
                Convert.FromHexString("133457799BBCDFF1")));
            AssertThrows<ArgumentNullException>(() => adapter.Transform(null!, new byte[8]));
            AssertThrows<ArgumentException>(() => adapter.Transform(new byte[8], new byte[7]));
        });
        AddTest(tests, "DEAL: different blocks, master keys, input ownership and rekeying", () =>
        {
            var random = new Random(2026);
            var cipher = new DealCipher();
            foreach (int keySize in new[] { 16, 24, 32 })
            {
                for (int iteration = 0; iteration < 12; iteration++)
                {
                    byte[] key = new byte[keySize];
                    byte[] input = new byte[16];
                    random.NextBytes(key);
                    random.NextBytes(input);
                    byte[] original = (byte[])input.Clone();
                    cipher.SetKey(key);
                    byte[] encrypted = cipher.EncryptBlock(input);
                    Array.Clear(key);
                    AssertEqual(original, cipher.DecryptBlock(encrypted));
                    AssertEqual(original, input);
                    AssertEqual(encrypted, cipher.EncryptBlock(input));
                }
            }
        });
        AddTest(tests, "DEAL: validation and failed rekey preserve prepared keys", () =>
        {
            var cipher = new DealCipher();
            AssertThrows<InvalidOperationException>(() => cipher.EncryptBlock(new byte[16]));
            AssertThrows<ArgumentNullException>(() => cipher.SetKey(null!));
            cipher.SetKey(new byte[16]);
            byte[] expected = cipher.EncryptBlock(new byte[16]);
            foreach (int length in new[] { 0, 8, 15, 17, 23, 25, 31, 33 })
            {
                AssertThrows<ArgumentException>(() => cipher.SetKey(new byte[length]));
                AssertEqual(expected, cipher.EncryptBlock(new byte[16]));
            }

            AssertThrows<ArgumentNullException>(() => cipher.DecryptBlock(null!));
            AssertThrows<ArgumentException>(() => cipher.EncryptBlock(new byte[15]));
            AssertThrows<ArgumentException>(() => cipher.DecryptBlock(new byte[17]));
        });
        return TestSupport.RunAsync(tests);
    }
}
