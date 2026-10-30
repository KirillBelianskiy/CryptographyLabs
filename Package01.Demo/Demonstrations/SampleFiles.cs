using System.Text;

namespace Package01.Demo.Demonstrations;

// Small valid files keep the demonstration independent of external codecs.
internal static class SampleFiles
{
    internal static IReadOnlyList<string> Names { get; } =
        ["image.bmp", "music.wav", "sample.cs", "text.txt", "video.y4m"];

    internal static async Task CreateAsync(string directory)
    {
        Directory.CreateDirectory(directory);
        await File.WriteAllTextAsync(Path.Combine(directory, "text.txt"),
            "Основы криптографии. DES и DEAL: проверка файлов.\n");
        await File.WriteAllTextAsync(Path.Combine(directory, "sample.cs"),
            """
            namespace Sample;

            public static class Example
            {
                public static int Add(int left, int right) => left + right;
            }
            """);
        await File.WriteAllBytesAsync(Path.Combine(directory, "image.bmp"), CreateBitmap());
        await File.WriteAllBytesAsync(Path.Combine(directory, "music.wav"), CreateMusic());
        await File.WriteAllBytesAsync(Path.Combine(directory, "video.y4m"), CreateVideo());
    }

    private static byte[] CreateBitmap()
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        writer.Write(Encoding.ASCII.GetBytes("BM"));
        writer.Write(70);
        writer.Write(0);
        writer.Write(54);
        writer.Write(40);
        writer.Write(2);
        writer.Write(2);
        writer.Write((short)1);
        writer.Write((short)24);
        writer.Write(0);
        writer.Write(16);
        writer.Write(2835);
        writer.Write(2835);
        writer.Write(0);
        writer.Write(0);
        writer.Write(new byte[]
        {
            0, 0, 255, 0, 255, 0, 0, 0,
            255, 0, 0, 255, 255, 255, 0, 0
        });
        return stream.ToArray();
    }

    private static byte[] CreateMusic()
    {
        const int SampleRate = 8000;
        const int SamplesPerNote = 400;
        double[] notes = [261.63, 329.63, 392.00, 523.25];
        int dataLength = notes.Length * SamplesPerNote * 2;
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        writer.Write(Encoding.ASCII.GetBytes("RIFF"));
        writer.Write(36 + dataLength);
        writer.Write(Encoding.ASCII.GetBytes("WAVEfmt "));
        writer.Write(16);
        writer.Write((short)1);
        writer.Write((short)1);
        writer.Write(SampleRate);
        writer.Write(SampleRate * 2);
        writer.Write((short)2);
        writer.Write((short)16);
        writer.Write(Encoding.ASCII.GetBytes("data"));
        writer.Write(dataLength);
        foreach (double frequency in notes)
        {
            for (int sample = 0; sample < SamplesPerNote; sample++)
            {
                double phase = 2 * Math.PI * frequency * sample / SampleRate;
                writer.Write((short)(8000 * Math.Sin(phase)));
            }
        }

        return stream.ToArray();
    }

    private static byte[] CreateVideo()
    {
        using var stream = new MemoryStream();
        stream.Write(Encoding.ASCII.GetBytes(
            "YUV4MPEG2 W2 H2 F25:1 Ip A1:1 C420jpeg\n"));
        for (int frame = 0; frame < 10; frame++)
        {
            stream.Write(Encoding.ASCII.GetBytes("FRAME\n"));
            byte brightness = (byte)(16 + frame * 20);
            stream.Write(new byte[]
            {
                brightness, brightness, brightness, brightness, 128, 128
            });
        }

        return stream.ToArray();
    }
}
