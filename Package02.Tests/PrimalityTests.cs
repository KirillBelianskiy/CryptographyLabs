using System.Numerics;

using NUnit.Framework;

using Package02.Primality;

namespace Package02.Tests;

[TestFixture]
public sealed class PrimalityTests
{
    private static IEnumerable<ProbabilisticPrimalityTest> CreateTests()
    {
        yield return new FermatPrimalityTest();
        yield return new SolovayStrassenPrimalityTest();
        yield return new MillerRabinPrimalityTest();
    }

    [Test]
    public void PrimeAndCompositeClassificationAgreesWithTrialDivision()
    {
        foreach (ProbabilisticPrimalityTest test in CreateTests())
        {
            for (int n = -2; n <= 600; n++)
            {
                bool expected = n >= 2 && !Enumerable.Range(2, Math.Max(0, (int)Math.Sqrt(Math.Max(0, n)) - 1))
                    .Any(divisor => n % divisor == 0);
                Assert.That(test.IsProbablePrime(n, 0.999999999999), Is.EqualTo(expected),
                    $"{test.GetType().Name}, n={n}");
            }
        }
    }

    [Test]
    public void SingleRoundsExposePseudoprimesAndWitnessesDeterministically()
    {
        Assert.That(new FermatPrimalityTest().PassesRound(561, 2), Is.True);
        Assert.That(new SolovayStrassenPrimalityTest().PassesRound(561, 2), Is.True);
        Assert.That(new MillerRabinPrimalityTest().PassesRound(561, 2), Is.False);
        Assert.That(new MillerRabinPrimalityTest().PassesRound(2047, 2), Is.True);
        Assert.That(new MillerRabinPrimalityTest().PassesRound(2047, 3), Is.False);
        Assert.That(new FermatPrimalityTest().PassesRound(561, 3), Is.False);
    }

    [Test]
    public void AllPrimeBasesPassAndCompositeWitnessBoundsHold()
    {
        var solovay = new SolovayStrassenPrimalityTest();
        var miller = new MillerRabinPrimalityTest();
        foreach (int n in new[] { 5, 7, 11, 17, 97, 101 })
        {
            foreach (ProbabilisticPrimalityTest test in CreateTests())
            {
                for (int basis = 2; basis <= n - 2; basis++)
                {
                    Assert.That(test.PassesRound(n, basis), Is.True);
                }
            }
        }

        foreach (int n in new[] { 9, 15, 21, 25, 341, 561, 1105, 1729, 2047 })
        {
            int solovayLiars = Enumerable.Range(2, n - 3).Count(a => solovay.PassesRound(n, a));
            int millerLiars = Enumerable.Range(2, n - 3).Count(a => miller.PassesRound(n, a));
            Assert.That(2 * solovayLiars, Is.LessThanOrEqualTo(n - 3));
            Assert.That(4 * millerLiars, Is.LessThanOrEqualTo(n - 3));
        }
    }

    [Test]
    public void ProbabilityValidationAndRoundCounts()
    {
        foreach (ProbabilisticPrimalityTest test in CreateTests())
        {
            foreach (double probability in new[] { double.NaN, double.PositiveInfinity, 0.49, 1.0 })
            {
                Assert.Throws<ArgumentOutOfRangeException>(() => test.IsProbablePrime(2, probability));
            }

            Assert.That(test.GetRoundCount(0.5), Is.EqualTo(1));
            Assert.That(test.IsProbablePrime(101, double.BitDecrement(1)), Is.True);
            Assert.Throws<ArgumentOutOfRangeException>(() => test.PassesRound(4, 2));
            Assert.Throws<ArgumentOutOfRangeException>(() => test.PassesRound(7, 1));
        }

        Assert.That(new SolovayStrassenPrimalityTest().GetRoundCount(0.99), Is.EqualTo(7));
        Assert.That(new MillerRabinPrimalityTest().GetRoundCount(0.99), Is.EqualTo(4));
    }

    [Test]
    public void RandomCandidatesHaveExactWidthAndRange()
    {
        foreach (int bits in new[] { 2, 7, 8, 9, 64, 129 })
        {
            for (int i = 0; i < 100; i++)
            {
                BigInteger candidate = RandomIntegers.OddWithBitLength(bits);
                Assert.That(candidate.GetBitLength(), Is.EqualTo(bits));
                Assert.That(candidate.IsEven, Is.False);
                BigInteger sample = RandomIntegers.Below(candidate);
                Assert.That(sample >= 0 && sample < candidate, Is.True);
            }
        }

        Assert.That(RandomIntegers.Below(1), Is.EqualTo(BigInteger.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => RandomIntegers.Below(0));
    }
}
