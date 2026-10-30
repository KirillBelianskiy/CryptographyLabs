using System.Numerics;

using NUnit.Framework;

using Package02.Arithmetic;
using Package02.Rsa;

namespace Package02.Tests;

[TestFixture]
public sealed class RsaTests
{
    [Test]
    public void TextbookExampleMatchesKnownCiphertext()
    {
        var publicKey = new RsaPublicKey(3233, 17);
        var privateKey = new RsaPrivateKey(3233, 2753);
        Assert.That(RsaService.EncryptNumber(65, publicKey), Is.EqualTo(new BigInteger(2790)));
        Assert.That(RsaService.DecryptNumber(2790, privateKey), Is.EqualTo(new BigInteger(65)));
        foreach (int value in new[] { 0, 1, 53, 61, 3232 })
        {
            Assert.That(RsaService.DecryptNumber(RsaService.EncryptNumber(value, publicKey), privateKey),
                Is.EqualTo(new BigInteger(value)));
        }
    }

    [TestCase(RsaService.PrimalityTestKind.Fermat)]
    [TestCase(RsaService.PrimalityTestKind.SolovayStrassen)]
    [TestCase(RsaService.PrimalityTestKind.MillerRabin)]
    public void GeneratedKeysRoundTripAllByteValuesAndResistWiener(RsaService.PrimalityTestKind kind)
    {
        var service = new RsaService(kind, 0.999999999999, 32);
        Assert.Throws<InvalidOperationException>(() => service.Encrypt([]));
        RsaKeyPair first = service.GenerateKeyPair();
        Assert.That(service.CurrentKeyPair, Is.SameAs(first));
        Assert.That(first.P.GetBitLength(), Is.EqualTo(32));
        Assert.That(first.Q.GetBitLength(), Is.EqualTo(32));
        Assert.That(first.P, Is.Not.EqualTo(first.Q));
        Assert.That(BigInteger.Abs(first.P - first.Q) >= (BigInteger.One << 29), Is.True);
        Assert.That(first.PrivateKey.Exponent > NumberTheory.IntegerSquareRoot(first.PublicKey.Modulus), Is.True);
        Assert.That(first.PublicKey.Exponent * first.PrivateKey.Exponent % first.EulerPhi, Is.EqualTo(BigInteger.One));
        Assert.That(new WienerAttackService().Attack(first.PublicKey).Success, Is.False);
        BigInteger root = NumberTheory.IntegerSquareRoot(first.PublicKey.Modulus);
        BigInteger ceilRoot = root * root == first.PublicKey.Modulus ? root : root + 1;
        Assert.That((first.P + first.Q) / 2 - ceilRoot, Is.GreaterThan(new BigInteger(1000)));
        byte[][] samples =
        [
            [], [0], [0, 0, 0, 0], [255],
            Enumerable.Range(0, 256).Select(value => (byte)value).Concat(new byte[10]).ToArray(),
            new byte[7], new byte[8], new byte[14], new byte[15]
        ];
        foreach (byte[] sample in samples)
        {
            Assert.That(service.Decrypt(service.Encrypt(sample)), Is.EqualTo(sample));
        }

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Assert.Throws<OperationCanceledException>(() => service.GenerateKeyPair(cancellation.Token));
        Assert.That(service.CurrentKeyPair, Is.SameAs(first));
        RsaKeyPair second = service.GenerateKeyPair();
        Assert.That(service.CurrentKeyPair, Is.SameAs(second));
        byte[] ciphertext = RsaService.Encrypt([0, 42, 0], first.PublicKey);
        Assert.That(RsaService.Decrypt(ciphertext, first.PrivateKey), Is.EqualTo(new byte[] { 0, 42, 0 }));
    }

    [Test]
    public void MinimumBitLengthAndMaximumRepresentableConfidenceWork()
    {
        foreach (RsaService.PrimalityTestKind kind in Enum.GetValues<RsaService.PrimalityTestKind>())
        {
            var service = new RsaService(kind, double.BitDecrement(1), 16);
            RsaKeyPair pair = service.GenerateKeyPair();
            Assert.That(pair.P.GetBitLength(), Is.EqualTo(16));
            Assert.That(pair.Q.GetBitLength(), Is.EqualTo(16));
            Assert.That(service.Decrypt(service.Encrypt([0, 255, 0])), Is.EqualTo(new byte[] { 0, 255, 0 }));
        }
    }

    [Test]
    public void VulnerableGeneratorAndAttackRecoverSeveralKeys()
    {
        var generator = new WienerVulnerableKeyGenerator(32, 0.999999999999);
        var attack = new WienerAttackService();
        for (int i = 0; i < 20; i++)
        {
            RsaKeyPair pair = generator.Generate();
            WienerAttackResult result = attack.Attack(pair.PublicKey);
            Assert.That(result.Success, Is.True);
            Assert.That(result.PrivateExponent, Is.EqualTo(pair.PrivateKey.Exponent));
            Assert.That(result.EulerPhi, Is.EqualTo(pair.EulerPhi));
            Assert.That(result.Convergents.Any(fraction => fraction.Denominator == pair.PrivateKey.Exponent), Is.True);
            Assert.That(attack.TryRecoverFactors(pair.PublicKey.Modulus, result.EulerPhi!.Value, out BigInteger p,
                out BigInteger q), Is.True);
            Assert.That(p * q, Is.EqualTo(pair.PublicKey.Modulus));
            BigInteger cipher = RsaService.EncryptNumber(12345, pair.PublicKey);
            Assert.That(RsaService.DecryptNumber(cipher,
                new RsaPrivateKey(pair.PublicKey.Modulus, result.PrivateExponent!.Value)), Is.EqualTo(new BigInteger(12345)));
        }
    }

    [Test]
    public void WienerAttackMatchesPublishedSmallExample()
    {
        WienerAttackResult result = new WienerAttackService().Attack(new RsaPublicKey(90581, 17993));
        Assert.That(result.PrivateExponent, Is.EqualTo(new BigInteger(5)));
        Assert.That(result.EulerPhi, Is.EqualTo(new BigInteger(89964)));
        Assert.That(result.Convergents.Take(3), Is.EqualTo(new[]
        {
            new Convergent(0, 1), new Convergent(1, 5), new Convergent(29, 146)
        }));
        WienerAttackResult failure = new WienerAttackService().Attack(new RsaPublicKey(3233, 17));
        Assert.That(failure.Success, Is.False);
        Assert.That(failure.PrivateExponent, Is.Null);
        Assert.That(failure.Convergents, Is.Not.Empty);
    }

    [Test]
    public void InvalidInputsAndCancellationAreRejected()
    {
        var publicKey = new RsaPublicKey(3233, 17);
        var privateKey = new RsaPrivateKey(3233, 2753);
        Assert.Throws<ArgumentOutOfRangeException>(() => RsaService.EncryptNumber(-1, publicKey));
        Assert.Throws<ArgumentOutOfRangeException>(() => RsaService.EncryptNumber(3233, publicKey));
        Assert.Throws<ArgumentOutOfRangeException>(() => RsaService.EncryptNumber(0, new RsaPublicKey(1, 1)));
        Assert.Throws<ArgumentException>(() => RsaService.Decrypt([0, 0, 0], privateKey));
        Assert.Throws<ArgumentException>(() => RsaService.Decrypt([255, 255, 255, 255], privateKey));
        Assert.Throws<ArgumentException>(() => RsaService.Decrypt([0, 0, 0, 1], privateKey));
        Assert.Throws<ArgumentOutOfRangeException>(() => RsaService.Decrypt([0, 0, 0, 1, 255, 255], privateKey));
        Assert.Throws<ArgumentOutOfRangeException>(() => new RsaService((RsaService.PrimalityTestKind)99, 0.99, 32));
        Assert.Throws<ArgumentOutOfRangeException>(() => new RsaService(RsaService.PrimalityTestKind.MillerRabin, 1, 32));
        Assert.Throws<ArgumentOutOfRangeException>(() => new WienerVulnerableKeyGenerator(8));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var service = new RsaService(RsaService.PrimalityTestKind.MillerRabin, 0.99, 32);
        Assert.Throws<OperationCanceledException>(() => service.GenerateKeyPair(cancellation.Token));
        Assert.That(service.CurrentKeyPair, Is.Null);
        Assert.Throws<OperationCanceledException>(() => new WienerVulnerableKeyGenerator().Generate(cancellation.Token));
    }
}
