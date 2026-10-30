using System.Numerics;

using Package02.Arithmetic;

namespace Package02.Primality;

public sealed class FermatPrimalityTest : ProbabilisticPrimalityTest
{
    protected override bool ExecuteRound(BigInteger value, BigInteger basis) =>
        NumberTheory.ModPow(basis, value - 1, value) == 1;

    protected override bool ConfirmResult(BigInteger value, double minimumProbability) =>
        new MillerRabinPrimalityTest().IsProbablePrime(value, minimumProbability);
}
