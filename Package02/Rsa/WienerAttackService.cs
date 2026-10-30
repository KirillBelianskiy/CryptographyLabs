using System.Numerics;

using Package02.Arithmetic;

namespace Package02.Rsa;

public readonly record struct Convergent(BigInteger Numerator, BigInteger Denominator);

public sealed record WienerAttackResult(
    BigInteger? PrivateExponent,
    BigInteger? EulerPhi,
    IReadOnlyList<Convergent> Convergents)
{
    public bool Success => PrivateExponent.HasValue;
}

public sealed class WienerAttackService
{
    public IReadOnlyList<Convergent> GetConvergents(BigInteger numerator, BigInteger denominator)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(numerator);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(denominator);
        var result = new List<Convergent>();
        BigInteger previousNumerator = 0;
        BigInteger currentNumerator = 1;
        BigInteger previousDenominator = 1;
        BigInteger currentDenominator = 0;
        while (denominator != 0)
        {
            BigInteger quotient = numerator / denominator;
            BigInteger nextNumerator = quotient * currentNumerator + previousNumerator;
            BigInteger nextDenominator = quotient * currentDenominator + previousDenominator;
            result.Add(new Convergent(nextNumerator, nextDenominator));
            (previousNumerator, currentNumerator) = (currentNumerator, nextNumerator);
            (previousDenominator, currentDenominator) = (currentDenominator, nextDenominator);
            (numerator, denominator) = (denominator, numerator % denominator);
        }

        return result.AsReadOnly();
    }

    public WienerAttackResult Attack(RsaPublicKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Modulus < 4 || key.Exponent <= 1 || key.Exponent >= key.Modulus)
        {
            throw new ArgumentOutOfRangeException(nameof(key));
        }

        IReadOnlyList<Convergent> convergents = GetConvergents(key.Exponent, key.Modulus);
        foreach (Convergent convergent in convergents)
        {
            BigInteger k = convergent.Numerator;
            BigInteger d = convergent.Denominator;
            BigInteger product = key.Exponent * d - 1;
            if (k == 0 || product <= 0 || product % k != 0)
            {
                continue;
            }

            BigInteger phi = product / k;
            if (TryRecoverFactors(key.Modulus, phi, out _, out _))
            {
                return new WienerAttackResult(d, phi, convergents);
            }
        }

        return new WienerAttackResult(null, null, convergents);
    }

    public bool TryRecoverFactors(BigInteger modulus, BigInteger phi, out BigInteger p, out BigInteger q)
    {
        p = 0;
        q = 0;
        if (modulus < 4 || phi <= 0 || phi >= modulus)
        {
            return false;
        }

        BigInteger sum = modulus - phi + 1;
        BigInteger discriminant = sum * sum - 4 * modulus;
        if (discriminant < 0)
        {
            return false;
        }

        BigInteger root = NumberTheory.IntegerSquareRoot(discriminant);
        if (root * root != discriminant || !(sum + root).IsEven)
        {
            return false;
        }

        p = (sum - root) / 2;
        q = (sum + root) / 2;
        return p > 1 && q > 1 && p != q && p * q == modulus;
    }
}
