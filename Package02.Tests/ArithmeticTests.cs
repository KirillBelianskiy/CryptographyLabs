using System.Numerics;

using NUnit.Framework;

using Package02.Arithmetic;

namespace Package02.Tests;

[TestFixture]
public sealed class ArithmeticTests
{
    [Test]
    public void GcdVariantsAndBezoutAgreeForSignedInputs()
    {
        for (int a = -40; a <= 40; a++)
        {
            for (int b = -40; b <= 40; b++)
            {
                var expected = BigInteger.GreatestCommonDivisor(a, b);
                BezoutResult result = NumberTheory.ExtendedGcd(a, b);
                Assert.That(NumberTheory.Gcd(a, b), Is.EqualTo(expected));
                Assert.That(NumberTheory.BinaryGcd(a, b), Is.EqualTo(expected));
                Assert.That(result.Gcd, Is.EqualTo(expected));
                Assert.That(a * result.X + b * result.Y, Is.EqualTo(expected));
            }
        }
    }

    [Test]
    public void ModularPowerMatchesIndependentOracle()
    {
        for (int a = -10; a <= 10; a++)
        {
            for (int modulus = 1; modulus <= 20; modulus++)
            {
                for (int exponent = 0; exponent <= 12; exponent++)
                {
                    var expected = BigInteger.ModPow((a % modulus + modulus) % modulus, exponent, modulus);
                    Assert.That(NumberTheory.ModPow(a, exponent, modulus), Is.EqualTo(expected));
                }
            }
        }

        BigInteger large = (BigInteger.One << 300) + 117;
        Assert.That(NumberTheory.ModPow(large, 12345, large - 2),
            Is.EqualTo(BigInteger.ModPow(large, 12345, large - 2)));
    }

    [Test]
    public void EulerMethodsAgreeOnRange()
    {
        for (int value = 1; value <= 500; value++)
        {
            BigInteger expected = NumberTheory.EulerByDefinition(value);
            Assert.That(NumberTheory.EulerByFactorization(value), Is.EqualTo(expected), $"factorization, n={value}");
            Assert.That(NumberTheory.EulerByFourier(value), Is.EqualTo(expected), $"Fourier, n={value}");
        }

        Assert.That(NumberTheory.EulerByFourier(100_000), Is.EqualTo(new BigInteger(40_000)));
    }

    [TestCase(1, 1)]
    [TestCase(2, 1)]
    [TestCase(8, 2)]
    [TestCase(16, 4)]
    [TestCase(27, 18)]
    [TestCase(360, 12)]
    [TestCase(561, 80)]
    public void CarmichaelMatchesKnownValues(int value, int expected) =>
        Assert.That(NumberTheory.Carmichael(value), Is.EqualTo(new BigInteger(expected)));

    [Test]
    public void CarmichaelIsLeastUniversalExponentForSmallInputs()
    {
        for (int n = 2; n <= 80; n++)
        {
            int expected = 1;
            while (Enumerable.Range(1, n - 1).Any(a => NumberTheory.Gcd(a, n) == 1 &&
                NumberTheory.ModPow(a, expected, n) != 1))
            {
                expected++;
            }

            Assert.That(NumberTheory.Carmichael(n), Is.EqualTo(new BigInteger(expected)));
        }
    }

    [TestCase(5, 11, 1)]
    [TestCase(2, 11, -1)]
    [TestCase(22, 11, 0)]
    [TestCase(-1, 7, -1)]
    public void LegendreMatchesKnownSymbols(int numerator, int prime, int expected) =>
        Assert.That(NumberTheory.Legendre(numerator, prime), Is.EqualTo(expected));

    [TestCase(5, 21, 1)]
    [TestCase(3, 21, 0)]
    [TestCase(-1, 7, -1)]
    [TestCase(2, 15, 1)]
    [TestCase(0, 1, 1)]
    public void JacobiMatchesKnownSymbols(int numerator, int denominator, int expected) =>
        Assert.That(NumberTheory.Jacobi(numerator, denominator), Is.EqualTo(expected));

    [Test]
    public void JacobiAgreesWithProductOfLegendreSymbols()
    {
        for (int denominator = 3; denominator < 100; denominator += 2)
        {
            for (int numerator = -10; numerator <= 30; numerator++)
            {
                int expected = 1;
                foreach (PrimePower factor in NumberTheory.Factorize(denominator))
                {
                    for (int i = 0; i < factor.Exponent; i++)
                    {
                        expected *= NumberTheory.Legendre(numerator, factor.Prime);
                    }
                }

                Assert.That(NumberTheory.Jacobi(numerator, denominator), Is.EqualTo(expected));
            }
        }
    }

    [Test]
    public void SquareRootHasExactFloorIncludingLargeSquares()
    {
        for (int i = 0; i < 1000; i++)
        {
            BigInteger root = NumberTheory.IntegerSquareRoot(i);
            Assert.That(root * root <= i && (root + 1) * (root + 1) > i, Is.True);
        }

        BigInteger large = (BigInteger.One << 512) + 123;
        Assert.That(NumberTheory.IntegerSquareRoot(large * large), Is.EqualTo(large));
        Assert.That(NumberTheory.IntegerSquareRoot(large * large - 1), Is.EqualTo(large - 1));
    }

    [Test]
    public void InvalidArgumentsAreRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => NumberTheory.ModPow(2, -1, 5));
        Assert.Throws<ArgumentOutOfRangeException>(() => NumberTheory.ModPow(2, 1, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => NumberTheory.Jacobi(1, 2));
        Assert.Throws<ArgumentOutOfRangeException>(() => NumberTheory.Factorize(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => NumberTheory.EulerByDefinition(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => NumberTheory.EulerByFourier(100_001));
        Assert.Throws<ArgumentOutOfRangeException>(() => NumberTheory.IntegerSquareRoot(-1));
        Assert.Throws<ArgumentException>(() => NumberTheory.ModInverse(6, 9));
        Assert.That(NumberTheory.ModInverse(-3, 11), Is.EqualTo(new BigInteger(7)));
    }
}
