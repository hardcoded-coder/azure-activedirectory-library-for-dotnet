//----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

using Microsoft.IdentityModel.Clients.ActiveDirectory;

using Test.ADAL.Common;

namespace Test.ADAL.NET.Friend
{
    class RecorderHttpWebRequestFactory : IHttpWebRequestFactory
    {
        public IHttpWebRequest Create(string uri)
        {
            return new RecorderHttpWebRequest(uri);
        }

        public IHttpWebResponse CreateResponse(WebResponse response)
        {
            var replayerWebResponse = response as ReplayerWebResponse;
            var httpWebResponse = response as HttpWebResponse;
            var httpClientWebResponse = response as HttpClientWebResponse;
            WebHeaderCollection responseHeaders;
            HttpStatusCode statusCode;
            if (replayerWebResponse != null)
            {
                statusCode = replayerWebResponse.StatusCode;
                responseHeaders = replayerWebResponse.Headers;
            }
            else if (httpWebResponse != null)
            {
                statusCode = httpWebResponse.StatusCode;
                responseHeaders = httpWebResponse.Headers;
            }
            else if (httpClientWebResponse != null)
            {
                statusCode = httpClientWebResponse.StatusCode;
                responseHeaders = httpClientWebResponse.Headers;
            }
            else
            {
                statusCode = HttpStatusCode.NotImplemented;
                responseHeaders = new WebHeaderCollection();
            }

            var headers = new Dictionary<string, string>();
            foreach (var key in response.Headers.AllKeys)
            {
                headers[key] = responseHeaders[key];
            }

            var responseStream = response.GetResponseStream();
            return new RecorderHttpWebResponse(responseStream, headers, statusCode,
                delegate
                {
                    responseStream.Close();
                    responseStream = null;
                } );
        }

        public async Task<IHttpWebResponse> CreateResponseAsync(HttpResponseMessage response)
        {
            var replayerWebResponse = response as ReplayerResponseMessage;
            var httpWebResponse = response as HttpResponseMessage;
            HttpStatusCode statusCode;
            if (replayerWebResponse != null)
            {
                statusCode = replayerWebResponse.StatusCode;
            }
            else if (httpWebResponse != null)
            {
                statusCode = httpWebResponse.StatusCode;
            }
            else
            {
                statusCode = HttpStatusCode.NotImplemented;
            }

            var headers = new Dictionary<string, string>();
            foreach (var kvp in response.Headers)
            {
                headers[kvp.Key] = kvp.Value.First();
            }

            return new RecorderHttpWebResponse(await response.Content.ReadAsStreamAsync(), headers, statusCode, null);
        }
    }
}
