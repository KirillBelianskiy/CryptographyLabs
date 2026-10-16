using System.Security.Cryptography;

using Package01.Abstractions;

namespace Package01.Modes;

internal sealed class BlockModeProcessor
{
    private readonly ISymmetricBlockCipher _cipher;
    private readonly CipherMode _mode;
    private readonly int _blockSize;
    private readonly byte[] _delta;
    private readonly byte[] _counter;
    private byte[] _feedback;
    private byte[] _previousPlain;

    internal BlockModeProcessor(
        ISymmetricBlockCipher cipher,
        CipherMode mode,
        byte[] iv,
        byte[] delta)
    {
        _cipher = cipher;
        _mode = mode;
        _blockSize = cipher.BlockSizeBytes;
        _delta = delta;
        _counter = (byte[])iv.Clone();
        _feedback = (byte[])iv.Clone();
        _previousPlain = new byte[iv.Length];
    }

    internal byte[] Transform(
        byte[] input,
        bool decrypt,
        CancellationToken cancellationToken)
    {
        if (input.Length % _blockSize != 0)
        {
            throw new ArgumentException("Input must contain complete blocks.", nameof(input));
        }

        int count = input.Length / _blockSize;
        byte[] output = new byte[input.Length];
        if (count == 0)
        {
            return output;
        }

        if (_mode == CipherMode.Ecb)
        {
            ForBlocks(count, cancellationToken, index =>
            {
                byte[] block = GetBlock(input, index);
                PutBlock(output, index, CryptBlock(block, decrypt));
            });
        }
        else if (_mode is CipherMode.Ctr or CipherMode.RandomDelta)
        {
            byte[][] counters = new byte[count][];
            for (int index = 0; index < count; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                counters[index] = (byte[])_counter.Clone();
                AddBigEndian(_counter, _delta);
            }

            ForBlocks(count, cancellationToken, index =>
            {
                byte[] mask = CryptBlock(counters[index], decrypt: false);
                Xor(mask, GetBlock(input, index));
                PutBlock(output, index, mask);
            });
        }
        else if (decrypt && (_mode is CipherMode.Cbc or CipherMode.Cfb))
        {
            byte[] initialFeedback = (byte[])_feedback.Clone();
            ForBlocks(count, cancellationToken, index =>
            {
                byte[] previous = index == 0 ? initialFeedback : GetBlock(input, index - 1);
                byte[] block = _mode == CipherMode.Cbc
                    ? CryptBlock(GetBlock(input, index), decrypt: true)
                    : CryptBlock(previous, decrypt: false);
                Xor(block, _mode == CipherMode.Cbc ? previous : GetBlock(input, index));
                PutBlock(output, index, block);
            });

            _feedback = GetBlock(input, count - 1);
        }
        else
        {
            for (int index = 0; index < count; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                byte[] block = GetBlock(input, index);
                byte[] transformed;

                switch (_mode)
                {
                    case CipherMode.Cbc:
                        Xor(block, _feedback);
                        transformed = CryptBlock(block, decrypt: false);
                        _feedback = (byte[])transformed.Clone();
                        break;

                    case CipherMode.Pcbc:
                        if (decrypt)
                        {
                            // Preserve C_i even if the cipher modifies its input
                            // or returns that same array as its output.
                            byte[] ciphertext = (byte[])block.Clone();
                            transformed = CryptBlock(block, decrypt: true);
                            Xor(transformed, _feedback);
                            Xor(transformed, _previousPlain);
                            _feedback = ciphertext;
                            _previousPlain = (byte[])transformed.Clone();
                        }
                        else
                        {
                            byte[] plain = (byte[])block.Clone();
                            Xor(block, _feedback);
                            Xor(block, _previousPlain);
                            transformed = CryptBlock(block, decrypt: false);
                            _feedback = (byte[])transformed.Clone();
                            _previousPlain = plain;
                        }

                        break;

                    case CipherMode.Cfb:
                        transformed = CryptBlock(_feedback, decrypt: false);
                        Xor(transformed, block);
                        _feedback = (byte[])transformed.Clone();
                        break;

                    case CipherMode.Ofb:
                        _feedback = CryptBlock(_feedback, decrypt: false);
                        transformed = (byte[])_feedback.Clone();
                        Xor(transformed, block);
                        break;

                    default:
                        throw new InvalidOperationException("Unsupported cipher mode.");
                }

                PutBlock(output, index, transformed);
            }
        }

        return output;
    }

    private byte[] CryptBlock(byte[] input, bool decrypt)
    {
        byte[] result = decrypt ? _cipher.DecryptBlock(input) : _cipher.EncryptBlock(input);
        if (result is null || result.Length != _blockSize)
        {
            throw new CryptographicException("The block cipher returned an invalid block.");
        }

        return result;
    }

    private byte[] GetBlock(byte[] input, int index)
    {
        byte[] block = new byte[_blockSize];
        Buffer.BlockCopy(input, index * _blockSize, block, 0, _blockSize);
        return block;
    }

    private void PutBlock(byte[] output, int index, byte[] block) =>
        Buffer.BlockCopy(block, 0, output, index * _blockSize, _blockSize);

    private static void Xor(byte[] target, byte[] other)
    {
        if (target.Length != other.Length)
        {
            throw new ArgumentException("XOR operands must have equal lengths.");
        }

        for (int i = 0; i < target.Length; i++)
        {
            target[i] ^= other[i];
        }
    }

    private static void AddBigEndian(byte[] counter, byte[] delta)
    {
        int carry = 0;
        for (int i = counter.Length - 1; i >= 0; i--)
        {
            int sum = counter[i] + delta[i] + carry;
            counter[i] = (byte)sum;
            carry = sum >> 8;
        }
    }

    private static void ForBlocks(
        int count,
        CancellationToken cancellationToken,
        Action<int> action)
    {
        if (count < 64)
        {
            for (int index = 0; index < count; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                action(index);
            }
        }
        else
        {
            Parallel.For(
                0,
                count,
                new ParallelOptions { CancellationToken = cancellationToken },
                action);
        }
    }

}
