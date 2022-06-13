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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;
using System.Security.Cryptography;
using PBKDF1DotNet;

namespace PBKDF1DotNetTests
{
    [TestClass]
    public class Pbkdf1Tests
    {
        [TestMethod]
        public void Test1()
        {
            var password = Encoding.UTF8.GetBytes("password");
            var salt = Encoding.UTF8.GetBytes("t99g57haGwVhXXqe");
            int iterations = 1000000;
            int outputLength = 32;
            byte[] derivedKey = Pbkdf1.DeriveBytes(password, salt, iterations, outputLength);
            byte[] expectedKey = new PasswordDeriveBytes(password, salt, HashAlgorithmName.SHA512.Name, iterations).GetBytes(outputLength);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(derivedKey, expectedKey));
        }

        [TestMethod]
        public void Test2()
        {
            var password = Array.Empty<byte>();
            var salt = Encoding.UTF8.GetBytes("5cZmY7kUGPz8MzyW");
            int iterations = 200000;
            int outputLength = 32;
            byte[] derivedKey = Pbkdf1.DeriveBytes(password, salt, iterations, outputLength);
            byte[] expectedKey = new PasswordDeriveBytes(password, salt, HashAlgorithmName.SHA512.Name, iterations).GetBytes(outputLength);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(derivedKey, expectedKey));
        }

        [TestMethod]
        public void Test3()
        {
            var password = Encoding.UTF8.GetBytes("O02HT4%6FejXaqzs[Z+6N5rP$");
            var salt = Encoding.UTF8.GetBytes("5e55yP3z24yeDCJ7");
            int iterations = 1;
            int outputLength = 32;
            byte[] derivedKey = Pbkdf1.DeriveBytes(password, salt, iterations, outputLength);
            byte[] expectedKey = new PasswordDeriveBytes(password, salt, HashAlgorithmName.SHA512.Name, iterations).GetBytes(outputLength);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(derivedKey, expectedKey));
        }

        [TestMethod]
        public void Test4()
        {
            var password = Encoding.UTF8.GetBytes("{#|du_{rLA^{wcRSXY?xDm00t");
            var salt = Encoding.UTF8.GetBytes("Ur6MagyzuHhPPxJ9");
            int iterations = 2;
            int outputLength = 32;
            byte[] derivedKey = Pbkdf1.DeriveBytes(password, salt, iterations, outputLength);
            byte[] expectedKey = new PasswordDeriveBytes(password, salt, HashAlgorithmName.SHA512.Name, iterations).GetBytes(outputLength);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(derivedKey, expectedKey));
        }

        [TestMethod]
        public void Test5()
        {
            var password = Encoding.UTF8.GetBytes("Spa<]DS.B9[z>dEbYS.O./C2R");
            var salt = Encoding.UTF8.GetBytes("ZA6W8TPecSqXmq5M");
            int iterations = 200000;
            int outputLength = 16;
            byte[] derivedKey = Pbkdf1.DeriveBytes(password, salt, iterations, outputLength);
            byte[] expectedKey = new PasswordDeriveBytes(password, salt, HashAlgorithmName.SHA512.Name, iterations).GetBytes(outputLength);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(derivedKey, expectedKey));
        }

        [TestMethod]
        public void Test6()
        {
            var password = Encoding.UTF8.GetBytes("_;_I3E:g9%dD@04Vx5JrpsVZ9");
            var salt = Encoding.UTF8.GetBytes("839dGz99z5axKfXH");
            int iterations = 200000;
            int outputLength = 64;
            byte[] derivedKey = Pbkdf1.DeriveBytes(password, salt, iterations, outputLength);
            byte[] expectedKey = new PasswordDeriveBytes(password, salt, HashAlgorithmName.SHA512.Name, iterations).GetBytes(outputLength);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(derivedKey, expectedKey));
        }
    }
}