using System.Buffers.Binary;
using System.Numerics;

using Package02.Arithmetic;
using Package02.Primality;

namespace Package02.Rsa;

public sealed class RsaService
{
    public enum PrimalityTestKind
    {
        Fermat,
        SolovayStrassen,
        MillerRabin
    }

    public RsaService(PrimalityTestKind testKind, double minimumProbability, int primeBitLength)
    {
        Generator = new KeyGenerator(testKind, minimumProbability, primeBitLength);
    }

    public KeyGenerator Generator { get; }

    public RsaKeyPair? CurrentKeyPair { get; private set; }

    public RsaKeyPair GenerateKeyPair(CancellationToken cancellationToken = default)
    {
        RsaKeyPair pair = Generator.Generate(cancellationToken);
        CurrentKeyPair = pair;
        return pair;
    }

    public byte[] Encrypt(byte[] data) => Encrypt(data, RequireKeys().PublicKey);

    public byte[] Decrypt(byte[] data) => Decrypt(data, RequireKeys().PrivateKey);

    public static BigInteger EncryptNumber(BigInteger value, RsaPublicKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return TransformNumber(value, key.Modulus, key.Exponent);
    }

    public static BigInteger DecryptNumber(BigInteger value, RsaPrivateKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return TransformNumber(value, key.Modulus, key.Exponent);
    }

    public static byte[] Encrypt(byte[] data, RsaPublicKey key)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(key);
        ValidateKey(key.Modulus, key.Exponent);
        int plainSize = GetPlainBlockSize(key.Modulus);
        int cipherSize = checked((int)((key.Modulus.GetBitLength() + 7) / 8));
        int blocks = checked((int)((data.LongLength + plainSize - 1) / plainSize));
        byte[] output = new byte[checked(sizeof(int) + blocks * cipherSize)];
        BinaryPrimitives.WriteInt32BigEndian(output, data.Length);
        for (int i = 0; i < blocks; i++)
        {
            int offset = i * plainSize;
            int length = Math.Min(plainSize, data.Length - offset);
            var message = new BigInteger(data.AsSpan(offset, length), isUnsigned: true, isBigEndian: true);
            byte[] encrypted = EncryptNumber(message, key).ToByteArray(isUnsigned: true, isBigEndian: true);
            encrypted.CopyTo(output.AsSpan(sizeof(int) + (i + 1) * cipherSize - encrypted.Length));
        }

        return output;
    }

    public static byte[] Decrypt(byte[] data, RsaPrivateKey key)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(key);
        ValidateKey(key.Modulus, key.Exponent);
        int plainSize = GetPlainBlockSize(key.Modulus);
        int cipherSize = checked((int)((key.Modulus.GetBitLength() + 7) / 8));
        if (data.Length < sizeof(int))
        {
            throw new ArgumentException("Missing ciphertext length header.", nameof(data));
        }

        int length = BinaryPrimitives.ReadInt32BigEndian(data);
        long blocks = length < 0 ? -1 : (length + (long)plainSize - 1) / plainSize;
        if (length < 0 || sizeof(int) + blocks * cipherSize != data.LongLength)
        {
            throw new ArgumentException("Ciphertext length does not match its header.", nameof(data));
        }

        byte[] output = new byte[length];
        for (int i = 0; i < blocks; i++)
        {
            var encrypted = new BigInteger(
                data.AsSpan(sizeof(int) + i * cipherSize, cipherSize), isUnsigned: true, isBigEndian: true);
            byte[] message = DecryptNumber(encrypted, key).ToByteArray(isUnsigned: true, isBigEndian: true);
            int blockLength = Math.Min(plainSize, length - i * plainSize);
            if (message.Length > blockLength)
            {
                throw new ArgumentException("Decrypted block exceeds its declared length.", nameof(data));
            }

            message.CopyTo(output.AsSpan(i * plainSize + blockLength - message.Length));
        }

        return output;
    }

    private RsaKeyPair RequireKeys() => CurrentKeyPair ??
        throw new InvalidOperationException("Generate a key pair first.");

    private static int GetPlainBlockSize(BigInteger modulus)
    {
        int size = checked((int)((modulus.GetBitLength() - 1) / 8));
        if (size < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(modulus), "Byte encryption requires a modulus >= 256.");
        }

        return size;
    }

    private static void ValidateKey(BigInteger modulus, BigInteger exponent)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(modulus, new BigInteger(2));
        if (exponent <= 0 || exponent >= modulus)
        {
            throw new ArgumentOutOfRangeException(nameof(exponent));
        }
    }

    private static BigInteger TransformNumber(BigInteger value, BigInteger modulus, BigInteger exponent)
    {
        ValidateKey(modulus, exponent);
        if (value < 0 || value >= modulus)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Expected 0 <= value < modulus.");
        }

        return NumberTheory.ModPow(value, exponent, modulus);
    }

    public sealed class KeyGenerator
    {
        private readonly IPrimalityTest _test;
        private readonly double _minimumProbability;
        private readonly int _primeBitLength;

        public KeyGenerator(PrimalityTestKind testKind, double minimumProbability, int primeBitLength)
        {
            ProbabilisticPrimalityTest.ValidateProbability(minimumProbability);
            ArgumentOutOfRangeException.ThrowIfLessThan(primeBitLength, 16);
            _test = testKind switch
            {
                PrimalityTestKind.Fermat => new FermatPrimalityTest(),
                PrimalityTestKind.SolovayStrassen => new SolovayStrassenPrimalityTest(),
                PrimalityTestKind.MillerRabin => new MillerRabinPrimalityTest(),
                _ => throw new ArgumentOutOfRangeException(nameof(testKind))
            };
            _minimumProbability = minimumProbability;
            _primeBitLength = primeBitLength;
        }

        public RsaKeyPair Generate(CancellationToken cancellationToken = default)
        {
            BigInteger exponent = 65_537;
            BigInteger minimumGap = BigInteger.One << (_primeBitLength - 3);
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                BigInteger p = GeneratePrime(cancellationToken);
                BigInteger q = GeneratePrime(cancellationToken);
                BigInteger modulus = p * q;
                BigInteger phi = (p - 1) * (q - 1);
                if (p == q || BigInteger.Abs(p - q) < minimumGap || NumberTheory.Gcd(exponent, phi) != 1)
                {
                    continue;
                }

                BigInteger privateExponent = NumberTheory.ModInverse(exponent, phi);
                // A stronger restriction than the small-d boundary of Wiener's theorem.
                if (privateExponent <= NumberTheory.IntegerSquareRoot(modulus))
                {
                    continue;
                }

                var publicKey = new RsaPublicKey(modulus, exponent);
                if (new WienerAttackService().Attack(publicKey).Success)
                {
                    continue;
                }

                return new RsaKeyPair(publicKey,
                    new RsaPrivateKey(modulus, privateExponent), p, q);
            }
        }

        internal BigInteger GeneratePrime(CancellationToken cancellationToken)
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                BigInteger candidate = RandomIntegers.OddWithBitLength(_primeBitLength);
                // Independent extra screening halves the per-candidate error bound
                // without rounding a probability extremely close to one up to one.
                if (_test.IsProbablePrime(candidate, _minimumProbability) &&
                    _test.IsProbablePrime(candidate, 0.5))
                {
                    return candidate;
                }
            }
        }
    }
}
