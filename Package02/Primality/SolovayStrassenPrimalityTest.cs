using System.Numerics;

using Package02.Arithmetic;

namespace Package02.Primality;

public sealed class SolovayStrassenPrimalityTest : ProbabilisticPrimalityTest
{
    protected override bool ExecuteRound(BigInteger value, BigInteger basis)
    {
        int symbol = NumberTheory.Jacobi(basis, value);
        return symbol != 0 && NumberTheory.ModPow(basis, (value - 1) / 2, value) ==
            NumberTheory.Normalize(symbol, value);
    }
}
