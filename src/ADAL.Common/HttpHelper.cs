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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.Serialization.Json;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Clients.ActiveDirectory
{
    internal static class HttpHelper
    {
        public static T DeserializeResponse<T>(Stream responseStream)
        {
            DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(T));

            if (responseStream == null)
            {
                return default(T);
            }

            using (Stream stream = responseStream)
            {
                return ((T)serializer.ReadObject(stream));
            }
        }

        public static string ReadStreamContent(Stream stream)
        {
            using (StreamReader sr = new StreamReader(stream))
            {
                return sr.ReadToEnd();
            }
        }

        public static string CheckForExtraQueryParameter(string url)
        {
            string extraQueryParameter = PlatformSpecificHelper.GetEnvironmentVariable("ExtraQueryParameter");
            string delimiter = (url.IndexOf('?') > 0) ? "&" : "?";
            if (!string.IsNullOrWhiteSpace(extraQueryParameter))
            {
                url += string.Concat(delimiter, extraQueryParameter);
            }

            return url;
        }

        public static void AddCorrelationIdHeadersToRequest(Dictionary<string, string> headers, CallState callState)
        {
            if (callState == null || callState.CorrelationId == Guid.Empty)
            {
                return;
            }

            headers[OAuthHeader.CorrelationId] = callState.CorrelationId.ToString();
            headers[OAuthHeader.RequestCorrelationIdInResponse] = "true";
        }

        public static void VerifyCorrelationIdHeaderInReponse(Dictionary<string, string> headers, CallState callState)
        {
            if (callState == null || callState.CorrelationId == Guid.Empty)
            {
                return;
            }

            foreach (string reponseHeaderKey in headers.Keys)
            {
                string trimmedKey = reponseHeaderKey.Trim();
                if (string.Compare(trimmedKey, OAuthHeader.CorrelationId, StringComparison.OrdinalIgnoreCase) == 0)
                {
                    string correlationIdHeader = headers[trimmedKey].Trim();
                    Guid correlationIdInResponse;
                    if (!Guid.TryParse(correlationIdHeader, out correlationIdInResponse))
                    {
                        Logger.Information(callState, "Returned correlation id '{0}' is not in GUID format.", correlationIdHeader);
                    }
                    else if (correlationIdInResponse != callState.CorrelationId)
                    {
                        Logger.Information(callState, "Returned correlation id '{0}' does not match the sent correlation id '{1}'", correlationIdHeader, callState.CorrelationId);
                    }

                    break;
                }
            }
        }
    }
}
