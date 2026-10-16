namespace Package01.Padding;

/// <summary>Selects the byte-padding convention.</summary>
public enum PaddingMode
{
    /// <summary>Pads with zero bytes; original trailing zeros are ambiguous.</summary>
    Zeros,
    /// <summary>Zero bytes followed by the padding length.</summary>
    AnsiX923,
    /// <summary>Each padding byte contains the padding length.</summary>
    Pkcs7,
    /// <summary>Random bytes followed by the padding length.</summary>
    Iso10126
}
