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
    internal class HttpClientWebResponse : WebResponse
    {
        private readonly Stream responseStream;
        private readonly HttpResponseMessage response;

        private readonly WebHeaderCollection headers;

        public HttpClientWebResponse(HttpResponseMessage response, Stream responseStream)
        {
            this.response = response;
            this.responseStream = responseStream;

            this.headers = new WebHeaderCollection();
            foreach (var kvp in response.Headers)
            {
                this.headers[kvp.Key] = kvp.Value.First();
            }

            foreach (var kvp in response.Content.Headers)
            {
                this.headers[kvp.Key] = kvp.Value.First();
            }
        }

        public HttpStatusCode StatusCode
        {
            get
            {
                return this.response.StatusCode;
            }                
        }

        public override long ContentLength
        {
            get
            {
                return this.response.Content.Headers.ContentLength ?? 0;
            }
        }

        public override string ContentType
        {
            get
            {
                return this.response.Content.Headers.ContentType.ToString();
            }
        }

        public override Uri ResponseUri
        {
            get
            {
                return this.response.RequestMessage.RequestUri;
            }
        }

        public override WebHeaderCollection Headers
        {
            get
            {
                return this.headers;
            }
        }

        public override Stream GetResponseStream()
        {
            return this.responseStream;
        }
    }
}