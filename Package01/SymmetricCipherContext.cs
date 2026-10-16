using System.Security.Cryptography;

using Package01.Abstractions;
using Package01.Modes;
using Package01.Padding;

using CipherMode = Package01.Modes.CipherMode;
using PaddingMode = Package01.Padding.PaddingMode;

namespace Package01;

public sealed class SymmetricCipherContext
{
    private const int FileBufferSize = 64 * 1024;

    private readonly ISymmetricBlockCipher _cipher;
    private readonly CipherMode _mode;
    private readonly PaddingMode _padding;
    private readonly int _blockSize;
    private readonly byte[] _iv;
    private readonly byte[] _delta;

    public SymmetricCipherContext(
        ISymmetricBlockCipher cipher,
        byte[] key,
        CipherMode mode,
        PaddingMode padding,
        byte[]? iv = null,
        params object[] modeParameters)
    {
        _cipher = cipher ??
                  throw new ArgumentNullException(nameof(cipher), "Block cipher cannot be null.");

        if (key is null)
        {
            throw new ArgumentNullException(nameof(key), "Key cannot be null.");
        }

        if (key.Length == 0)
        {
            throw new ArgumentException("Key cannot be empty.", nameof(key));
        }

        if (modeParameters is null)
        {
            throw new ArgumentNullException(nameof(modeParameters), "Mode parameters cannot be null.");
        }

        if (!Enum.IsDefined(mode))
        {
            throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unsupported cipher mode.");
        }

        if (!Enum.IsDefined(padding))
        {
            throw new ArgumentOutOfRangeException(nameof(padding), padding, "Unsupported padding mode.");
        }

        _blockSize = cipher.BlockSizeBytes;
        if (_blockSize < 1 || (padding != PaddingMode.Zeros && _blockSize > 255))
        {
            throw new ArgumentOutOfRangeException(
                nameof(cipher),
                "Block size must be positive; length-byte padding supports at most 255 bytes.");
        }

        if (mode == CipherMode.Ecb)
        {
            if (iv is not null)
            {
                throw new ArgumentException("ECB does not use an IV.", nameof(iv));
            }

            _iv = new byte[_blockSize];
        }
        else
        {
            if (iv is null || iv.Length != _blockSize)
            {
                throw new ArgumentException("IV must contain exactly one block.", nameof(iv));
            }

            _iv = (byte[])iv.Clone();
        }

        _delta = new byte[_blockSize];
        if (mode == CipherMode.RandomDelta)
        {
            if (modeParameters.Length != 1 ||
                modeParameters[0] is not byte[] delta ||
                delta.Length != _blockSize ||
                delta.All(value => value == 0))
            {
                throw new ArgumentException(
                    "RandomDelta requires one nonzero byte[] delta of block size.",
                    nameof(modeParameters));
            }

            _delta = (byte[])delta.Clone();
        }
        else if (modeParameters.Length != 0)
        {
            throw new ArgumentException(
                "This mode has no additional parameters.",
                nameof(modeParameters));
        }
        else if (mode == CipherMode.Ctr)
        {
            _delta[^1] = 1;
        }

        _mode = mode;
        _padding = padding;
        _cipher.SetKey((byte[])key.Clone());
    }

    public Task<byte[]> EncryptAsync(byte[] input, CancellationToken cancellationToken = default)
    {
        if (input is null)
        {
            throw new ArgumentNullException(nameof(input), "Input cannot be null.");
        }

        byte[] snapshot = (byte[])input.Clone();
        return Task.Run(() => EncryptCore(snapshot, cancellationToken), cancellationToken);
    }

    public Task<byte[]> DecryptAsync(byte[] input, CancellationToken cancellationToken = default)
    {
        if (input is null)
        {
            throw new ArgumentNullException(nameof(input), "Input cannot be null.");
        }

        byte[] snapshot = (byte[])input.Clone();
        return Task.Run(() => DecryptCore(snapshot, cancellationToken), cancellationToken);
    }

    public Task EncryptAsync(
        string inputPath,
        string outputPath,
        CancellationToken cancellationToken = default) =>
        TransformFileAsync(inputPath, outputPath, decrypt: false, cancellationToken);

    public Task DecryptAsync(
        string inputPath,
        string outputPath,
        CancellationToken cancellationToken = default) =>
        TransformFileAsync(inputPath, outputPath, decrypt: true, cancellationToken);

    private byte[] EncryptCore(byte[] input, CancellationToken cancellationToken)
    {
        byte[] padded = PaddingCodec.Pad(input, _blockSize, _padding);
        return CreateProcessor().Transform(padded, decrypt: false, cancellationToken);
    }

    private byte[] DecryptCore(byte[] input, CancellationToken cancellationToken)
    {
        if (input.Length % _blockSize != 0 ||
            (input.Length == 0 && _padding != PaddingMode.Zeros))
        {
            throw new CryptographicException("Ciphertext must contain complete blocks and padding.");
        }

        byte[] output = CreateProcessor().Transform(
            input,
            decrypt: true,
            cancellationToken);
        if (output.Length == 0)
        {
            return output;
        }

        int unpaddedLength;
        if (_padding == PaddingMode.Zeros)
        {
            unpaddedLength = output.Length;
            while (unpaddedLength > 0 && output[unpaddedLength - 1] == 0)
            {
                unpaddedLength--;
            }
        }
        else
        {
            int lastLength = PaddingCodec.GetUnpaddedLength(
                output.AsSpan(^_blockSize), _padding);
            unpaddedLength = output.Length - _blockSize + lastLength;
        }

        Array.Resize(ref output, unpaddedLength);
        return output;
    }

    private async Task TransformFileAsync(
        string inputPath,
        string outputPath,
        bool decrypt,
        CancellationToken cancellationToken)
    {
        ValidatePath(inputPath, nameof(inputPath));
        ValidatePath(outputPath, nameof(outputPath));

        string outputFullPath = Path.GetFullPath(outputPath);
        string directory = Path.GetDirectoryName(outputFullPath)!;
        string tempPath = Path.Combine(
            directory,
            $".{Path.GetFileName(outputFullPath)}.{Guid.NewGuid():N}.tmp");

        try
        {
            await TransformFileContentsAsync(inputPath, tempPath, decrypt, cancellationToken);

            cancellationToken.ThrowIfCancellationRequested();
            File.Move(tempPath, outputFullPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(tempPath))
            {
                File.Delete(tempPath);
            }
        }
    }

    private async Task TransformFileContentsAsync(
        string inputPath,
        string outputPath,
        bool decrypt,
        CancellationToken cancellationToken)
    {
        await using FileStream input = new(
            inputPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            FileBufferSize,
            useAsync: true);
        await using FileStream output = new(
            outputPath,
            FileMode.CreateNew,
            FileAccess.ReadWrite,
            FileShare.None,
            FileBufferSize,
            useAsync: true);

        BlockModeProcessor processor = CreateProcessor();
        int chunkSize = _blockSize * Math.Max(1, FileBufferSize / _blockSize);
        byte[] buffer = new byte[checked(chunkSize + _blockSize)];
        byte[]? lastPlainBlock = null;
        int buffered = 0;
        int read;

        while ((read = await input.ReadAsync(
                   buffer.AsMemory(buffered),
                   cancellationToken)) != 0)
        {
            buffered += read;
            int fullLength = buffered / _blockSize * _blockSize;
            if (fullLength == 0)
            {
                continue;
            }

            byte[] chunk = new byte[fullLength];
            Buffer.BlockCopy(buffer, 0, chunk, 0, fullLength);
            byte[] transformed = processor.Transform(
                chunk,
                decrypt,
                cancellationToken);

            if (decrypt)
            {
                if (lastPlainBlock is not null)
                {
                    await output.WriteAsync(lastPlainBlock, cancellationToken);
                }

                int precedingLength = transformed.Length - _blockSize;
                if (precedingLength > 0)
                {
                    await output.WriteAsync(
                        transformed.AsMemory(0, precedingLength),
                        cancellationToken);
                }

                lastPlainBlock = transformed[^_blockSize..];
            }
            else
            {
                await output.WriteAsync(transformed, cancellationToken);
            }

            buffered -= fullLength;
            Buffer.BlockCopy(buffer, fullLength, buffer, 0, buffered);
        }

        if (decrypt)
        {
            if (buffered != 0 ||
                (lastPlainBlock is null && _padding != PaddingMode.Zeros))
            {
                throw new CryptographicException("Ciphertext has an invalid length.");
            }

            if (lastPlainBlock is not null)
            {
                int length = PaddingCodec.GetUnpaddedLength(lastPlainBlock, _padding);
                await output.WriteAsync(
                    lastPlainBlock.AsMemory(0, length),
                    cancellationToken);
            }

            if (_padding == PaddingMode.Zeros)
            {
                await TrimTrailingZerosAsync(output, cancellationToken);
            }
        }
        else
        {
            byte[]? finalBlock = PaddingCodec.FinalBlock(
                buffer.AsSpan(0, buffered),
                _blockSize,
                _padding);
            if (finalBlock is not null)
            {
                byte[] encrypted = processor.Transform(
                    finalBlock,
                    decrypt: false,
                    cancellationToken);
                await output.WriteAsync(encrypted, cancellationToken);
            }
        }
    }

    private BlockModeProcessor CreateProcessor() =>
        new(_cipher, _mode, _iv, _delta);

    private static async Task TrimTrailingZerosAsync(
        FileStream output,
        CancellationToken cancellationToken)
    {
        await output.FlushAsync(cancellationToken);
        byte[] buffer = new byte[FileBufferSize];
        long position = output.Length;
        while (position > 0)
        {
            int count = (int)Math.Min(buffer.Length, position);
            long start = position - count;
            output.Position = start;
            await output.ReadExactlyAsync(
                buffer.AsMemory(0, count), cancellationToken);
            while (count > 0 && buffer[count - 1] == 0)
            {
                count--;
            }

            if (count != 0)
            {
                output.SetLength(start + count);
                return;
            }

            position = start;
        }

        output.SetLength(0);
    }

    private static void ValidatePath(string path, string parameterName)
    {
        if (path is null)
        {
            throw new ArgumentNullException(parameterName, "File path cannot be null.");
        }

        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("File path cannot be empty or whitespace.", parameterName);
        }
    }
}
