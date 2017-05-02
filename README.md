# Lib.Net.Http.EncryptedContentEncoding
[![NuGet version](https://badge.fury.io/nu/Lib.Net.Http.EncryptedContentEncoding.svg)](http://badge.fury.io/nu/Lib.Net.Http.EncryptedContentEncoding)

Lib.Net.Http.EncryptedContentEncoding is a library which adds [Encrypted Content-Encoding (aes128gcm)](https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-09) support to HttpClient.

## Getting Started

Lib.Net.Http.EncryptedContentEncoding is available on [NuGet](https://www.nuget.org/packages/Lib.Net.Http.EncryptedContentEncoding/).

```
PM>  Install-Package Lib.Net.Http.EncryptedContentEncoding
```

## Implementation Details and Usage Samples

There are blog posts available describing implementation details and showing usage samples:

- [Supporting Encrypted Content-Encoding in HttpClient (Part 1 of 2) - Encoding](https://tpeczek.com/2017/02/supporting-encrypted-content-encoding.html)
- [Supporting Encrypted Content-Encoding in HttpClient (Part 2 of 2) - Decoding](https://tpeczek.com/2017/03/supporting-encrypted-content-encoding.html)


## Bouncy Castle Dependency
Lib.Net.Http.EncryptedContentEncoding has a dependency on [Bouncy Castle](http://www.bouncycastle.org/csharp/). The .NET Framework version is using [BouncyCastle](https://www.nuget.org/packages/BouncyCastle/) package which is well known and widely downloaded, but the .NET Core version is using [BouncyCastle.CoreClr](https://www.nuget.org/packages/BouncyCastle.CoreClr/) package which is quite new and comes from different author. As those packages provide cryptography routines make sure you want to use them and remember that you can always download the source code and run your own build.

## Copyright and License
Copyright © 2017 Tomasz Pęczek

Licensed under the [MIT License](https://github.com/tpeczek/Lib.Net.Http.EncryptedContentEncoding/blob/master/LICENSE.md)
