﻿//----------------------------------------------------------------------
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
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.IdentityModel.Clients.ActiveDirectory.Internal;

namespace Test.ADAL.WinRT.Unit
{
    class ReplayerWebUI : ReplayerBase, IWebUI
    {
        private const string Delimiter = ":::";

        public ReplayerWebUI(PromptBehavior promptBehavior, bool useCorporateNetwork)
        {
        }

        public async Task<AuthorizationResult> AuthenticateAsync(Uri authorizationUri, Uri redirectUri, CallState callState)
        {
            string key = authorizationUri.AbsoluteUri + redirectUri.AbsoluteUri;

            if (IOMap.ContainsKey(key))
            {
                string value = IOMap[key];
                if (value[0] == 'P')
                {
                    return OAuth2Response.ParseAuthorizeResponse(value.Substring(1), callState);
                }
                
                if (value[0] == 'A')
                {
                    string []segments = value.Substring(1).Split(new [] { Delimiter }, StringSplitOptions.RemoveEmptyEntries);
                    return new AuthorizationResult(error: segments[0], errorDescription: segments[1]);
                }
            }

            return null;
        }
    }
}
