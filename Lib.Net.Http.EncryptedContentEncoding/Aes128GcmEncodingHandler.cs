using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Lib.Net.Http.EncryptedContentEncoding.Internals;

namespace Lib.Net.Http.EncryptedContentEncoding
{
    public sealed class Aes128GcmEncodingHandler : DelegatingHandler
    {
        #region Fields
        private readonly Func<string, byte[]> _keyLocator;
        #endregion

        #region Constructors
        public Aes128GcmEncodingHandler(Func<string, byte[]> keyLocator)
        {
            _keyLocator = keyLocator;
        }
        #endregion

        #region Methods
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            request.Headers.AcceptEncoding.Add(new StringWithQualityHeaderValue(Constants.ENCRYPTED_CONTENT_ENCODING));

            HttpResponseMessage response = await base.SendAsync(request, cancellationToken);

            if (response.Content.Headers.ContentEncoding.Contains(Constants.ENCRYPTED_CONTENT_ENCODING))
            {
                response.Content = new Aes128GcmDecodedContent(response.Content, _keyLocator);
            }

            return response;
        }
        #endregion
    }
}
