using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Lib.Net.Http.EncryptedContentEncoding.Internals;

namespace Lib.Net.Http.EncryptedContentEncoding
{
    /// <summary>
    /// The <see cref="DelegatingHandler"/> which wraps incoming response content in <see cref="Aes128GcmDecodedContent"/> based on Content-Encoding header value and sets Accept-Encoding header for outgoing request.
    /// </summary>
    public sealed class Aes128GcmEncodingHandler : DelegatingHandler
    {
        #region Fields
        private readonly Func<string, byte[]> _keyLocator;
        #endregion

        #region Constructors
        /// <summary>
        /// Instantiates a new <see cref="Aes128GcmEncodingHandler"/>.
        /// </summary>
        /// <param name="keyLocator">The function which is able to locate the keying material based on the keying material identificator.</param>
        public Aes128GcmEncodingHandler(Func<string, byte[]> keyLocator)
        {
            _keyLocator = keyLocator;
        }
        #endregion

        #region Methods
        /// <summary>
        /// Sends the request asynchronously.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <param name="cancellationToken">The cancelation token.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            request.Headers.AcceptEncoding.Add(new StringWithQualityHeaderValue(Constants.ENCRYPTED_CONTENT_ENCODING));

            HttpResponseMessage response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

            if (response.Content.Headers.ContentEncoding.Contains(Constants.ENCRYPTED_CONTENT_ENCODING))
            {
                response.Content = new Aes128GcmDecodedContent(response.Content, _keyLocator);
            }

            return response;
        }
        #endregion
    }
}
