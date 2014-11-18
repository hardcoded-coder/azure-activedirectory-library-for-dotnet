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
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Clients.ActiveDirectory
{
    internal class HttpClientWrapper : IHttpWebRequest
    {
        private string uri;
        private int timeoutInMilliSeconds = 30000;

        public HttpClientWrapper(string uri)
        {
            this.uri = uri;
            this.Headers = new Dictionary<string, string>();
        }

        public RequestParameters BodyParameters { get; set; }

        public string Accept { get; set; }

        public string ContentType { get; set; }

        public bool UseDefaultCredentials { get; set; }

        public Dictionary<string, string> Headers { get; private set; }

        public int TimeoutInMilliSeconds
        {
            set
            {
                this.timeoutInMilliSeconds = value;
            }        
        }

        public async Task<IHttpWebResponse> GetResponseSyncOrAsync(CallState callState)
        {
            using (HttpClient client = new HttpClient())
            {
                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue(this.Accept ?? "application/json"));
                foreach (KeyValuePair<string, string> kvp in Headers)
                {
                    client.DefaultRequestHeaders.Add(kvp.Key, kvp.Value);
                }

                client.Timeout = TimeSpan.FromMilliseconds(this.timeoutInMilliSeconds);

                HttpResponseMessage response = null;
                Stream responseStream = null;

                if (this.BodyParameters != null)
                {
                    var content = new FormUrlEncodedContent(this.BodyParameters.ToList());
                    response = await client.PostAsync(uri, content);
                }
                else
                {
                    response = await client.GetAsync(uri);
                }

                if (response.StatusCode == HttpStatusCode.OK)
                {
                    return await NetworkPlugin.HttpWebRequestFactory.CreateResponseAsync(response);
                }

                responseStream = await response.Content.ReadAsStreamAsync();
                responseStream.Position = 0;

                throw new WebException("To REPLACE", null, WebExceptionStatus.ProtocolError,
                    new HttpClientWebResponse(response, responseStream));
            }
        }
    }
}