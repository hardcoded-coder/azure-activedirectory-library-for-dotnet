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

using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Clients.ActiveDirectory
{
    internal class HttpWebRequestFactory : IHttpWebRequestFactory
    {
        public IHttpWebRequest Create(string uri)
        {
            return new HttpWebRequestWrapper(uri);
        }

        public IHttpWebResponse CreateResponse(WebResponse response)
        {
            var headers = new Dictionary<string, string>();
            if (response.Headers != null)
            {
                foreach (var key in response.Headers.AllKeys)
                {
                    headers[key] = response.Headers[key];
                }
            }

            var httpWebResponse = response as HttpWebResponse;
            HttpStatusCode statusCode = (httpWebResponse != null) ? httpWebResponse.StatusCode : HttpStatusCode.NotImplemented;

            return new HttpWebResponseWrapper(response.GetResponseStream(), headers, statusCode, PlatformSpecificHelper.CloseHttpWebResponse(response));
        }

        public async Task<IHttpWebResponse> CreateResponseAsync(HttpResponseMessage response)
        {
            var headers = new Dictionary<string, string>();
            if (response.Headers != null)
            {
                foreach (var kvp in response.Headers)
                {
                    headers[kvp.Key] = kvp.Value.First();
                }
            }

            return new HttpWebResponseWrapper(await response.Content.ReadAsStreamAsync(), headers, response.StatusCode, null);            
        }
    }
}