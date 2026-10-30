using System.Numerics;

using Package02.Arithmetic;

namespace Package02.Primality;

public sealed class MillerRabinPrimalityTest : ProbabilisticPrimalityTest
{
    protected override double RoundErrorBound => 0.25;

    protected override bool ExecuteRound(BigInteger value, BigInteger basis)
    {
        BigInteger oddPart = value - 1;
        int powers = 0;
        while (oddPart.IsEven)
        {
            oddPart >>= 1;
            powers++;
        }

        BigInteger residue = NumberTheory.ModPow(basis, oddPart, value);
        if (residue == 1 || residue == value - 1)
        {
            return true;
        }

        for (int i = 1; i < powers; i++)
        {
            residue = residue * residue % value;
            if (residue == value - 1)
            {
                return true;
            }

            if (residue == 1)
            {
                return false;
            }
        }

        return false;
    }
}
