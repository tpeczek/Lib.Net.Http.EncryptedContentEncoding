using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Lib.Net.Http.EncryptedContentEncoding.Internals;

namespace Lib.Net.Http.EncryptedContentEncoding
{
    /// <summary>
    /// A class representing an HTTP entity body decoded with aes128gcm encoding.
    /// </summary>
    public sealed class Aes128GcmDecodedContent : HttpContent
    {
        #region Fields
        private readonly HttpContent _contentToBeDecrypted;
        private readonly Func<string, byte[]> _keyLocator;
        #endregion

        #region Constructors
        /// <summary>
        /// Instantiates a new <see cref="Aes128GcmDecodedContent"/>.
        /// </summary>
        /// <param name="contentToBeDecrypted">The content which will be decoded.</param>
        /// <param name="keyLocator">The function which is able to locate the keying material based on the keying material identificator.</param>
        public Aes128GcmDecodedContent(HttpContent contentToBeDecrypted, Func<string, byte[]> keyLocator)
        {
            _contentToBeDecrypted = contentToBeDecrypted;
            _keyLocator = keyLocator;
        }
        #endregion

        #region Methods
        /// <summary>
        /// Serialize the HTTP content to a stream as an asynchronous operation.
        /// </summary>
        /// <param name="stream">The target stream.</param>
        /// <param name="context">Information about the transport (channel binding token, for example). This parameter may be null.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext context)
        {
            if (!_contentToBeDecrypted.Headers.ContentEncoding.Contains(Constants.ENCRYPTED_CONTENT_ENCODING))
            {
                throw new NotSupportedException($"Encryption type not supported or stream isn't encrypted. The only sypported encryption type is '{Constants.ENCRYPTED_CONTENT_ENCODING}'.");
            }

            Stream streamToBeDecrypted = await _contentToBeDecrypted.ReadAsStreamAsync().ConfigureAwait(false);

            await Aes128GcmEncoding.DecodeAsync(streamToBeDecrypted, stream, _keyLocator).ConfigureAwait(false);
        }

        /// <summary>
        /// Determines whether the HTTP content has a valid length in bytes.
        /// </summary>
        /// <param name="length">The length in bytes of the HTTP content.</param>
        /// <returns>True if length is a valid length, otherwise false.</returns>
        protected override bool TryComputeLength(out long length)
        {
            length = 0;

            return false;
        }
        #endregion
    }
}
