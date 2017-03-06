using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Lib.Net.Http.EncryptedContentEncoding.Internals;

namespace Lib.Net.Http.EncryptedContentEncoding
{
    public sealed class Aes128GcmDecodedContent : HttpContent
    {
        #region Fields
        private readonly HttpContent _contentToBeDecrypted;
        private readonly Func<string, byte[]> _keyLocator;
        #endregion

        #region Constructors
        public Aes128GcmDecodedContent(HttpContent contentToBeDecrypted, Func<string, byte[]> keyLocator)
        {
            _contentToBeDecrypted = contentToBeDecrypted;
            _keyLocator = keyLocator;
        }
        #endregion

        #region Methods
        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext context)
        {
            if (!_contentToBeDecrypted.Headers.ContentEncoding.Contains(Constants.ENCRYPTED_CONTENT_ENCODING))
            {
                throw new NotSupportedException($"Encryption type not supported or stream isn't encrypted. The only sypported encryption type is '{Constants.ENCRYPTED_CONTENT_ENCODING}'.");
            }

            Stream streamToBeDecrypted = await _contentToBeDecrypted.ReadAsStreamAsync();

            await Aes128GcmEncoding.DecodeAsync(streamToBeDecrypted, stream, _keyLocator);
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;

            return false;
        }
        #endregion
    }
}
