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
using System.Net;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Test.ADAL.Common;

namespace Test.ADAL.WinRT.Unit
{
    class ReplayerHttpWebResponse : IHttpWebResponse
    {
        private readonly HttpStatusCode statusCode;

        public ReplayerHttpWebResponse(WebResponse response)
        {
            this.ResponseStream = response.GetResponseStream();
            HttpWebResponse httpWebResponse = response as HttpWebResponse;
            if (httpWebResponse != null)
            {
                this.statusCode = httpWebResponse.StatusCode;
            }
            else
            {
                ReplayerWebResponse replayerWebResponse = response as ReplayerWebResponse;
                this.statusCode = (replayerWebResponse != null) ? replayerWebResponse.StatusCode : HttpStatusCode.NotImplemented;
            }

            this.Headers = new Dictionary<string, string>();
        }

        public ReplayerHttpWebResponse(string responseString, HttpStatusCode statusCode)
        {
            this.ResponseStream = new MemoryStream();
            SerializationHelper.StringToStream(responseString, ResponseStream);
            ResponseStream.Position = 0;
            this.statusCode = statusCode;
        }

        public HttpStatusCode StatusCode
        {
            get
            {
                return this.statusCode;
            }
        }

        public Dictionary<string, string> Headers { get; private set; }

        public Stream ResponseStream { get; private set; }

        public void Close()
        {
            this.ResponseStream = null;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (this.ResponseStream != null)
                {
                    ((IDisposable)this.ResponseStream).Dispose();
                    this.ResponseStream = null;
                }
            }
        }
    }
}
