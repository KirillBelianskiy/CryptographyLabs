using System.Numerics;

using Package02.Arithmetic;
using Package02.Primality;

namespace Package02.Rsa;

public sealed class WienerVulnerableKeyGenerator
{
    private readonly RsaService.KeyGenerator _primeGenerator;

    public WienerVulnerableKeyGenerator(int primeBitLength = 32, double minimumProbability = 0.999999)
    {
        _primeGenerator = new RsaService.KeyGenerator(
            RsaService.PrimalityTestKind.MillerRabin, minimumProbability, primeBitLength);
    }

    public RsaKeyPair Generate(CancellationToken cancellationToken = default)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            BigInteger p = _primeGenerator.GeneratePrime(cancellationToken);
            BigInteger q = _primeGenerator.GeneratePrime(cancellationToken);
            if (p == q)
            {
                continue;
            }

            BigInteger modulus = p * q;
            BigInteger phi = (p - 1) * (q - 1);
            BigInteger fourthRoot = NumberTheory.IntegerSquareRoot(NumberTheory.IntegerSquareRoot(modulus));
            BigInteger upperBound = fourthRoot / 4;
            BigInteger privateExponent = RandomIntegers.Below(upperBound - 3) + 3;
            if (NumberTheory.Gcd(privateExponent, phi) != 1)
            {
                continue;
            }

            BigInteger exponent = NumberTheory.ModInverse(privateExponent, phi);
            return new RsaKeyPair(new RsaPublicKey(modulus, exponent),
                new RsaPrivateKey(modulus, privateExponent), p, q);
        }
    }
}
