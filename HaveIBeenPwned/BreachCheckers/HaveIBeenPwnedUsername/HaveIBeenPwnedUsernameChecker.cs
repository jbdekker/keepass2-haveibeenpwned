using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using HaveIBeenPwned.BreachCheckers;
using KeePassExtensions;
using KeePass.Plugins;
using KeePassLib;
using KeePassLib.Collections;
using Newtonsoft.Json;

namespace HaveIBeenPwned.BreachCheckers.HaveIBeenPwnedUsername
{
    public class HaveIBeenPwnedUsernameChecker : BaseChecker
    {
        private const int DefaultRetries = 5;
        private const int RequestIntervalMilliseconds = 1600;
        private const string ApiKeyHeader = "hibp-api-key";
        private const string BreachedAccountUrl = "https://haveibeenpwned.com/api/v3/breachedaccount/";
        private static readonly Regex ApiKeyEntryTitle = new Regex(
            "^(hibp-?|haveibeenpwned)apikey$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        public HaveIBeenPwnedUsernameChecker(HttpClient httpClient, IPluginHost pluginHost)
            : base(httpClient, pluginHost)
        {
        }

        public override async Task<List<BreachedEntry>> CheckGroup(
            PwGroup group,
            bool expireEntries,
            bool oldEntriesOnly,
            bool ignoreDeleted,
            bool ignoreExpired,
            IProgress<ProgressItem> progressIndicator,
            Func<bool> canContinue)
        {
            progressIndicator.Report(new ProgressItem(0, "Searching for Have I Been Pwned API key..."));
            var apiKey = RetrieveApiKey();
            var entries = group.GetEntries(true)
                .Where(e => (!ignoreDeleted || !e.IsDeleted(pluginHost)) && (!ignoreExpired || !e.Expires))
                .ToArray();
            var usernames = entries
                .Select(e => e.Strings.ReadSafe(PwDefs.UserNameField).Trim())
                .Where(IsQueryableUsername)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            var accountsByDomain = BuildAccountIndex(entries);
            var breaches = await GetBreaches(progressIndicator, usernames, apiKey, canContinue);
            var breachedEntries = new List<BreachedEntry>();

            foreach (var breach in breaches)
            {
                if (!canContinue()) break;

                PwEntry pwEntry = null;
                Dictionary<string, PwEntry> accounts;
                if (!string.IsNullOrWhiteSpace(breach.Domain) && !string.IsNullOrWhiteSpace(breach.Username) &&
                    accountsByDomain.TryGetValue(breach.Domain, out accounts))
                {
                    accounts.TryGetValue(breach.Username, out pwEntry);
                }

                if (pwEntry != null && oldEntriesOnly && pwEntry.GetPasswordLastModified() >= breach.BreachDate)
                {
                    continue;
                }

                breachedEntries.Add(new BreachedEntry(pwEntry, breach));
                if (pwEntry != null && expireEntries) ExpireEntry(pwEntry);
            }

            return breachedEntries;
        }

        private async Task<List<HaveIBeenPwnedEntry>> GetBreaches(
            IProgress<ProgressItem> progressIndicator,
            string[] usernames,
            string apiKey,
            Func<bool> canContinue)
        {
            var allBreaches = new List<HaveIBeenPwnedEntry>();

            for (var i = 0; i < usernames.Length; i++)
            {
                if (!canContinue()) break;

                var username = usernames[i];
                var progress = (uint)(((i + 1) * 100) / usernames.Length);
                progressIndicator.Report(new ProgressItem(progress, string.Format("Checking \"{0}\" for breaches", username)));
                allBreaches.AddRange(await GetBreachesForUserName(username, apiKey, canContinue));

                if (i + 1 < usernames.Length && canContinue())
                {
                    await Task.Delay(RequestIntervalMilliseconds);
                }
            }

            return allBreaches;
        }

        private async Task<List<HaveIBeenPwnedEntry>> GetBreachesForUserName(
            string username,
            string apiKey,
            Func<bool> canContinue)
        {
            for (var retryCount = 0; ; retryCount++)
            {
                if (!canContinue()) return new List<HaveIBeenPwnedEntry>();

                TimeSpan retryDelay = TimeSpan.Zero;
                var shouldRetry = false;
                var requestUrl = BreachedAccountUrl + Uri.EscapeDataString(username) + "?truncateResponse=false";
                using (var request = new HttpRequestMessage(HttpMethod.Get, requestUrl))
                {
                    request.Headers.Add(ApiKeyHeader, apiKey);

                    using (var response = await client.SendAsync(request))
                    {
                        if (response.StatusCode == HttpStatusCode.NotFound)
                        {
                            return new List<HaveIBeenPwnedEntry>();
                        }

                        if (response.StatusCode == HttpStatusCode.Unauthorized)
                        {
                            throw new ApiKeyException("Have I Been Pwned rejected the API key. Check the key stored in the hibp-apikey entry.");
                        }

                        if ((int)response.StatusCode == 429)
                        {
                            if (retryCount >= DefaultRetries || !TryGetRetryDelay(response, out retryDelay))
                            {
                                throw new HaveIBeenPwnedAbortException("HIBP rate limit was exceeded without a usable Retry-After value.");
                            }

                            shouldRetry = true;
                        }
                        else
                        {
                            response.EnsureSuccessStatusCode();
                            var json = await response.Content.ReadAsStringAsync();
                            var breaches = JsonConvert.DeserializeObject<List<HaveIBeenPwnedEntry>>(json);
                            if (breaches == null) throw new InvalidDataException("HIBP returned an empty account breach response.");

                            foreach (var breach in breaches)
                            {
                                breach.Username = username;
                            }

                            return breaches;
                        }
                    }
                }

                if (shouldRetry) await Task.Delay(retryDelay);
            }
        }

        private static bool TryGetRetryDelay(HttpResponseMessage response, out TimeSpan retryDelay)
        {
            retryDelay = TimeSpan.Zero;
            var retryAfter = response.Headers.RetryAfter;
            if (retryAfter == null) return false;

            if (retryAfter.Delta.HasValue)
            {
                retryDelay = retryAfter.Delta.Value;
            }
            else if (retryAfter.Date.HasValue)
            {
                retryDelay = retryAfter.Date.Value - DateTimeOffset.UtcNow;
            }
            else
            {
                return false;
            }

            if (retryDelay < TimeSpan.Zero) retryDelay = TimeSpan.Zero;
            retryDelay += TimeSpan.FromMilliseconds(100);
            return true;
        }

        private static Dictionary<string, Dictionary<string, PwEntry>> BuildAccountIndex(IEnumerable<PwEntry> entries)
        {
            var accountsByDomain = new Dictionary<string, Dictionary<string, PwEntry>>(StringComparer.OrdinalIgnoreCase);

            foreach (var entry in entries)
            {
                var domain = entry.GetUrlDomain();
                var username = entry.Strings.ReadSafe(PwDefs.UserNameField).Trim();
                if (string.IsNullOrWhiteSpace(domain) || !IsQueryableUsername(username)) continue;

                Dictionary<string, PwEntry> accounts;
                if (!accountsByDomain.TryGetValue(domain, out accounts))
                {
                    accounts = new Dictionary<string, PwEntry>(StringComparer.OrdinalIgnoreCase);
                    accountsByDomain.Add(domain, accounts);
                }

                if (!accounts.ContainsKey(username)) accounts.Add(username, entry);
            }

            return accountsByDomain;
        }

        private static bool IsQueryableUsername(string username)
        {
            return !string.IsNullOrWhiteSpace(username) && !username.StartsWith("{REF:", StringComparison.OrdinalIgnoreCase);
        }

        private string RetrieveApiKey()
        {
            const string regex = "^(hibp-?|haveibeenpwned)apikey$";
            var candidates = new PwObjectList<PwEntry>();
            var searchParameters = new SearchParameters
            {
                SearchInTitles = true,
                SearchString = "apikey"
            };
            pluginHost.Database.RootGroup.SearchEntries(searchParameters, candidates);

            var apiKeys = candidates
                .Where(x => ApiKeyEntryTitle.IsMatch(x.Strings.ReadSafe(PwDefs.TitleField)))
                .ToArray();

            if (apiKeys.Length > 1)
            {
                throw new ApiKeyException(string.Format("Found more than one API key matching the pattern: {0}", regex));
            }

            if (apiKeys.Length == 0)
            {
                throw new ApiKeyException("No API key found. Create an entry named \"hibp-apikey\" and set its password to the key from https://haveibeenpwned.com/API/Key.");
            }

            var apiKey = apiKeys[0].Strings.ReadSafe(PwDefs.PasswordField);
            if (string.IsNullOrWhiteSpace(apiKey)) throw new ApiKeyException("The hibp-apikey entry has an empty password.");
            return apiKey;
        }
    }
}