/*
    PBKDF1.NET: A .NET implementation of PBKDF1.
    Copyright (c) 2022 Samuel Lucas
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

using System.Security.Cryptography;

namespace PBKDF1DotNet;

public static class Pbkdf1
{
    public const int SaltSize = 16;
    public const int MinIterations = 1;
    public const int DefaultIterations = 1500000;
    public const int MinOutputSize = 16;
    public const int DefaultOutputSize = 32;
    public const int MaxOutputSize = 64;

    public static byte[] DeriveBytes(byte[] password, byte[] salt, int iterations = DefaultIterations, int outputSize = DefaultOutputSize)
    {
        if (password == null) { throw new ArgumentNullException(nameof(password), $"{nameof(password)} cannot be null."); }
        if (salt == null || salt.Length != SaltSize) { throw new ArgumentOutOfRangeException(nameof(salt), $"{nameof(salt)} must be {SaltSize} bytes long."); }
        if (iterations < MinIterations) { throw new ArgumentOutOfRangeException(nameof(iterations), $"{nameof(iterations)} cannot be less than {MinIterations}."); }
        if (outputSize < MinOutputSize || outputSize > MaxOutputSize) { throw new ArgumentOutOfRangeException(nameof(outputSize), $"{nameof(outputSize)} must be between {MinOutputSize} and {MaxOutputSize} bytes."); }
        var hash = new byte[password.Length + salt.Length];
        Array.Copy(password, hash, password.Length);
        Array.Copy(salt, sourceIndex: 0, hash, destinationIndex: password.Length, salt.Length);
        using var sha512 = SHA512.Create();
        for (int i = 0; i < iterations; i++)
        {
            hash = sha512.ComputeHash(hash);
        }
        return hash[..outputSize];
    }
}