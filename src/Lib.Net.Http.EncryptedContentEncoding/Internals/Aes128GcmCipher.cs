using System;
#if NETSTANDARD2_1
using System.Security.Cryptography;
#else
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
#endif


namespace Lib.Net.Http.EncryptedContentEncoding.Internals
{
#if NETSTANDARD2_1
    internal class Aes128GcmCipher : IDisposable
    {
        private readonly AesGcm _aesGcmCipher;
        private readonly byte[] _contentEncryptionKeyInfoParameterHash;
        private readonly byte[] _nonceInfoParameterHash;

        public Aes128GcmCipher(byte[] contentEncryptionKeyInfoParameterHash, byte[] nonceInfoParameterHash)
        {
            // CEK = FIRST 16 OCTETS OF HMAC-SHA-256(PRK, CEK_INFO)
            _aesGcmCipher = new AesGcm(contentEncryptionKeyInfoParameterHash.AsSpan().Slice(0, Aes128GcmHelper.CONTENT_ENCRYPTION_KEY_LENGTH));
            _nonceInfoParameterHash = nonceInfoParameterHash;
        }

        public int Encrypt(byte[] plainText, int plainTextLength, byte[] cipherTextBuffer, ulong recordSequenceNumber)
        {
            Span<byte> cipherTextBufferSpan = cipherTextBuffer.AsSpan();

            _aesGcmCipher.Encrypt(
                Aes128GcmHelper.XorNonce(_nonceInfoParameterHash, recordSequenceNumber).AsSpan(),
                plainText.AsSpan().Slice(0, plainTextLength),
                cipherTextBufferSpan.Slice(0, plainTextLength),
                cipherTextBufferSpan.Slice(plainTextLength, Aes128GcmHelper.CONTENT_ENCRYPTION_KEY_LENGTH)
                );

            return plainTextLength + Aes128GcmHelper.CONTENT_ENCRYPTION_KEY_LENGTH;
        }

        public int Decrypt(byte[] cipherText, int cipherTextLength, byte[] plainTextBuffer, ulong recordSequenceNumber)
        {
            int textLength = cipherTextLength - Aes128GcmHelper.CONTENT_ENCRYPTION_KEY_LENGTH;

            Span<byte> cipherTextSpan = cipherText.AsSpan();

            _aesGcmCipher.Decrypt(
                Aes128GcmHelper.XorNonce(_nonceInfoParameterHash, recordSequenceNumber).AsSpan(),
                cipherTextSpan.Slice(0, textLength),
                cipherTextSpan.Slice(textLength, Aes128GcmHelper.CONTENT_ENCRYPTION_KEY_LENGTH),
                plainTextBuffer.AsSpan().Slice(0, textLength)
                );

            return textLength;
        }

        public void Dispose()
        {
            _aesGcmCipher.Dispose();
        }
    }
#else
    internal class Aes128GcmCipher : IDisposable
    {
        private readonly KeyParameter _key;
        private readonly byte[] _nonceInfoParameterHash;
        private readonly GcmBlockCipher _aes128GcmCipher;

        public Aes128GcmCipher(byte[] contentEncryptionKeyInfoParameterHash, byte[] nonceInfoParameterHash)
        {
            // CEK = FIRST 16 OCTETS OF HMAC-SHA-256(PRK, CEK_INFO)
            _key = new KeyParameter(contentEncryptionKeyInfoParameterHash, 0, Aes128GcmHelper.CONTENT_ENCRYPTION_KEY_LENGTH);

            _nonceInfoParameterHash = nonceInfoParameterHash;

            _aes128GcmCipher = new GcmBlockCipher(new AesEngine());
        }

        public int Encrypt(byte[] plainText, int plainTextLength, byte[] cipherTextBuffer, ulong recordSequenceNumber)
        {
            ConfigureAes128GcmCipher(_aes128GcmCipher, true, _key, _nonceInfoParameterHash, recordSequenceNumber);

            return Aes128GcmCipherProcessBytes(_aes128GcmCipher, plainText, plainTextLength, cipherTextBuffer);
        }

        public int Decrypt(byte[] cipherText, int cipherTextLength, byte[] plainTextBuffer, ulong recordSequenceNumber)
        {
            ConfigureAes128GcmCipher(_aes128GcmCipher, false, _key, _nonceInfoParameterHash, recordSequenceNumber);

            return Aes128GcmCipherProcessBytes(_aes128GcmCipher, cipherText, cipherTextLength, plainTextBuffer);
        }

        private static void ConfigureAes128GcmCipher(GcmBlockCipher aes128GcmCipher, bool forEncryption, KeyParameter key, byte[] nonceInfoParameterHash, ulong recordSequenceNumber)
        {
            aes128GcmCipher.Reset();
            AeadParameters aes128GcmParameters = new AeadParameters(key, 128, Aes128GcmHelper.XorNonce(nonceInfoParameterHash, recordSequenceNumber));
            aes128GcmCipher.Init(forEncryption, aes128GcmParameters);
        }

        private static int Aes128GcmCipherProcessBytes(GcmBlockCipher aes128GcmCipher, byte[] bytesToProcess, int bytesToProcessLength, byte[] processedBytesBuffer)
        {
            int processBytesCount = aes128GcmCipher.ProcessBytes(bytesToProcess, 0, bytesToProcessLength, processedBytesBuffer, 0);
            int doFinalBytesCount = aes128GcmCipher.DoFinal(processedBytesBuffer, processBytesCount);

            return processBytesCount + doFinalBytesCount;
        }

        public void Dispose()
        { }
    }
#endif
}
