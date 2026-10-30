using System.Numerics;

namespace Package02.Arithmetic;

public readonly record struct BezoutResult(BigInteger Gcd, BigInteger X, BigInteger Y);

public readonly record struct PrimePower(BigInteger Prime, int Exponent);

public static class NumberTheory
{
    public static BigInteger Normalize(BigInteger value, BigInteger modulus)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(modulus);
        BigInteger result = value % modulus;
        return result.Sign < 0 ? result + modulus : result;
    }

    public static BigInteger Gcd(BigInteger first, BigInteger second)
    {
        first = BigInteger.Abs(first);
        second = BigInteger.Abs(second);
        while (!second.IsZero)
        {
            (first, second) = (second, first % second);
        }

        return first;
    }

    public static BezoutResult ExtendedGcd(BigInteger first, BigInteger second)
    {
        var oldR = BigInteger.Abs(first);
        var r = BigInteger.Abs(second);
        BigInteger oldS = 1;
        BigInteger s = 0;
        BigInteger oldT = 0;
        BigInteger t = 1;
        while (!r.IsZero)
        {
            BigInteger quotient = oldR / r;
            (oldR, r) = (r, oldR - quotient * r);
            (oldS, s) = (s, oldS - quotient * s);
            (oldT, t) = (t, oldT - quotient * t);
        }

        return new BezoutResult(oldR, first.Sign * oldS, second.Sign * oldT);
    }

    public static BigInteger BinaryGcd(BigInteger first, BigInteger second)
    {
        first = BigInteger.Abs(first);
        second = BigInteger.Abs(second);
        if (first.IsZero || second.IsZero)
        {
            return first + second;
        }

        int commonPowers = 0;
        while (first.IsEven && second.IsEven)
        {
            first >>= 1;
            second >>= 1;
            commonPowers++;
        }

        while (first.IsEven)
        {
            first >>= 1;
        }

        do
        {
            while (second.IsEven)
            {
                second >>= 1;
            }

            if (first > second)
            {
                (first, second) = (second, first);
            }

            second -= first;
        }
        while (!second.IsZero);

        return first << commonPowers;
    }

    public static BigInteger ModPow(BigInteger value, BigInteger exponent, BigInteger modulus)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(exponent);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(modulus);
        BigInteger result = 1 % modulus;
        value = Normalize(value, modulus);
        while (exponent > 0)
        {
            if (!exponent.IsEven)
            {
                result = result * value % modulus;
            }

            value = value * value % modulus;
            exponent >>= 1;
        }

        return result;
    }

    public static BigInteger ModInverse(BigInteger value, BigInteger modulus)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(modulus, new BigInteger(2));
        BezoutResult result = ExtendedGcd(value, modulus);
        if (result.Gcd != 1)
        {
            throw new ArgumentException("The value has no inverse modulo the modulus.", nameof(value));
        }

        return Normalize(result.X, modulus);
    }

    public static int Jacobi(BigInteger numerator, BigInteger denominator)
    {
        if (denominator <= 0 || denominator.IsEven)
        {
            throw new ArgumentOutOfRangeException(nameof(denominator), "Expected a positive odd integer.");
        }

        numerator = Normalize(numerator, denominator);
        int sign = 1;
        while (!numerator.IsZero)
        {
            while (numerator.IsEven)
            {
                numerator >>= 1;
                BigInteger residue = denominator % 8;
                if (residue == 3 || residue == 5)
                {
                    sign = -sign;
                }
            }

            (numerator, denominator) = (denominator, numerator);
            if (numerator % 4 == 3 && denominator % 4 == 3)
            {
                sign = -sign;
            }

            numerator %= denominator;
        }

        return denominator == 1 ? sign : 0;
    }

    public static int Legendre(BigInteger numerator, BigInteger prime)
    {
        if (prime < 2 || (prime != 2 && prime.IsEven))
        {
            throw new ArgumentOutOfRangeException(nameof(prime));
        }

        if (prime == 2)
        {
            return Normalize(numerator, prime).IsZero ? 0 : 1;
        }

        BigInteger residue = ModPow(numerator, (prime - 1) / 2, prime);
        if (residue != 0 && residue != 1 && residue != prime - 1)
        {
            throw new ArgumentException("Euler's criterion failed; the denominator must be prime.", nameof(prime));
        }

        return residue == prime - 1 ? -1 : (int)residue;
    }

    public static IReadOnlyList<PrimePower> Factorize(BigInteger value)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(value);
        var factors = new List<PrimePower>();
        for (BigInteger divisor = 2; divisor <= value / divisor; divisor = divisor == 2 ? 3 : divisor + 2)
        {
            int exponent = 0;
            while (value % divisor == 0)
            {
                value /= divisor;
                exponent++;
            }

            if (exponent > 0)
            {
                factors.Add(new PrimePower(divisor, exponent));
            }
        }

        if (value > 1)
        {
            factors.Add(new PrimePower(value, 1));
        }

        return factors.AsReadOnly();
    }

    public static BigInteger EulerByDefinition(BigInteger value)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(value);
        BigInteger result = 0;
        for (BigInteger k = 1; k <= value; k++)
        {
            if (Gcd(k, value) == 1)
            {
                result++;
            }
        }

        return result;
    }

    public static BigInteger EulerByFactorization(BigInteger value)
    {
        BigInteger result = value;
        foreach (PrimePower factor in Factorize(value))
        {
            result = result / factor.Prime * (factor.Prime - 1);
        }

        return result;
    }

    public static BigInteger EulerByFourier(int value)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(value, 100_000);
        double sum = 0;
        double compensation = 0;
        for (int k = 1; k <= value; k++)
        {
            double term = (double)Gcd(k, value) * Math.Cos(2 * Math.PI * k / value);
            double corrected = term - compensation;
            double next = sum + corrected;
            compensation = next - sum - corrected;
            sum = next;
        }

        return new BigInteger(Math.Round(sum));
    }

    public static BigInteger Carmichael(BigInteger value)
    {
        BigInteger result = 1;
        foreach (PrimePower factor in Factorize(value))
        {
            BigInteger power = 1;
            for (int i = 1; i < factor.Exponent; i++)
            {
                power *= factor.Prime;
            }

            BigInteger component = factor.Prime == 2 && factor.Exponent >= 3
                ? power / 2
                : power * (factor.Prime - 1);
            result = result / Gcd(result, component) * component;
        }

        return result;
    }

    public static BigInteger IntegerSquareRoot(BigInteger value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        if (value < 2)
        {
            return value;
        }

        BigInteger estimate = BigInteger.One << checked((int)((value.GetBitLength() + 1) / 2));
        while (true)
        {
            BigInteger next = (estimate + value / estimate) / 2;
            if (next >= estimate)
            {
                return estimate;
            }

            estimate = next;
        }
    }
}
