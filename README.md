[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/samuel-lucas6/PBKDF1.NET/blob/main/LICENSE)

# PBKDF1.NET
A .NET implementation of [PBKDF1](https://datatracker.ietf.org/doc/html/rfc8018#section-5.1) using [SHA512](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha512?view=net-6.0).

> **Warning**
> 
> Do **NOT** use this algorithm. It is **NOT** strong or well designed. Use [Argon2](https://www.rfc-editor.org/rfc/rfc9106.html) or [scrypt](https://datatracker.ietf.org/doc/rfc7914/) instead.
