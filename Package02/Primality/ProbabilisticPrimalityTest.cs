using System.Numerics;

using Package02.Arithmetic;

namespace Package02.Primality;

public interface IPrimalityTest
{
    bool IsProbablePrime(BigInteger value, double minimumProbability);
}

public abstract class ProbabilisticPrimalityTest : IPrimalityTest
{
    protected virtual double RoundErrorBound => 0.5;

    public static void ValidateProbability(double minimumProbability)
    {
        if (!double.IsFinite(minimumProbability) || minimumProbability < 0.5 || minimumProbability >= 1)
        {
            throw new ArgumentOutOfRangeException(nameof(minimumProbability), "Expected 0.5 <= probability < 1.");
        }
    }

    public bool IsProbablePrime(BigInteger value, double minimumProbability)
    {
        ValidateProbability(minimumProbability);
        if (value < 2)
        {
            return false;
        }

        if (value == 2 || value == 3)
        {
            return true;
        }

        if (value.IsEven)
        {
            return false;
        }

        int rounds = GetRoundCount(minimumProbability);
        for (int i = 0; i < rounds; i++)
        {
            BigInteger basis = RandomIntegers.Below(value - 3) + 2;
            if (!PassesRound(value, basis))
            {
                return false;
            }
        }

        return ConfirmResult(value, minimumProbability);
    }

    public int GetRoundCount(double minimumProbability)
    {
        ValidateProbability(minimumProbability);
        int rounds = 1;
        double error = RoundErrorBound;
        while (error > 1 - minimumProbability)
        {
            error *= RoundErrorBound;
            rounds++;
        }

        return rounds;
    }

    public bool PassesRound(BigInteger value, BigInteger basis)
    {
        if (value < 5 || value.IsEven)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Expected an odd value >= 5.");
        }

        if (basis < 2 || basis > value - 2)
        {
            throw new ArgumentOutOfRangeException(nameof(basis));
        }

        return NumberTheory.Gcd(value, basis) == 1 && ExecuteRound(value, basis);
    }

    protected virtual bool ConfirmResult(BigInteger value, double minimumProbability) => true;

    protected abstract bool ExecuteRound(BigInteger value, BigInteger basis);
}
