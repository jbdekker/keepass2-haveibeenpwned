using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using HaveIBeenPwned.BreachCheckers;
using KeePassExtensions;
using KeePass.Plugins;
using KeePassLib;
using Newtonsoft.Json;

namespace HaveIBeenPwned.BreachCheckers.HaveIBeenPwnedSite
{
    public class HaveIBeenPwnedSiteChecker : BaseChecker
    {
        private const string BreachListUrl = "https://haveibeenpwned.com/api/v3/breaches";

        public HaveIBeenPwnedSiteChecker(HttpClient httpClient, IPluginHost pluginHost)
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
            progressIndicator.Report(new ProgressItem(0, "Getting Have I Been Pwned breach list..."));
            var breaches = await GetBreaches();
            var breachesByDomain = new Dictionary<string, List<HaveIBeenPwnedEntry>>(StringComparer.OrdinalIgnoreCase);

            foreach (var breach in breaches)
            {
                if (string.IsNullOrWhiteSpace(breach.Domain)) continue;

                List<HaveIBeenPwnedEntry> domainBreaches;
                if (!breachesByDomain.TryGetValue(breach.Domain, out domainBreaches))
                {
                    domainBreaches = new List<HaveIBeenPwnedEntry>();
                    breachesByDomain.Add(breach.Domain, domainBreaches);
                }

                domainBreaches.Add(breach);
            }


            var entries = group.GetEntries(true)
                .Where(e => (!ignoreDeleted || !e.IsDeleted(pluginHost)) && (!ignoreExpired || !e.Expires))
                .ToArray();
            var breachedEntries = new List<BreachedEntry>();

            foreach (var entry in entries)
            {
                if (!canContinue()) break;

                var domain = entry.GetUrlDomain();
                List<HaveIBeenPwnedEntry> domainBreaches;
                if (string.IsNullOrEmpty(domain) || !breachesByDomain.TryGetValue(domain, out domainBreaches)) continue;

                var lastModified = oldEntriesOnly ? entry.GetPasswordLastModified() : DateTime.MinValue;
                var addedBreach = false;
                foreach (var breach in domainBreaches)
                {
                    if (!canContinue()) break;
                    if (oldEntriesOnly && lastModified >= breach.BreachDate) continue;

                    breachedEntries.Add(new BreachedEntry(entry, breach));
                    addedBreach = true;
                }

                if (expireEntries && addedBreach) ExpireEntry(entry);
            }

            return breachedEntries;
        }

        private async Task<List<HaveIBeenPwnedEntry>> GetBreaches()
        {
            using (var response = await client.GetAsync(BreachListUrl))
            {
                response.EnsureSuccessStatusCode();
                var json = await response.Content.ReadAsStringAsync();
                var breaches = JsonConvert.DeserializeObject<List<HaveIBeenPwnedEntry>>(json);
                if (breaches == null) throw new InvalidDataException("HIBP returned an empty breach catalogue.");
                return breaches;
            }
        }
    }
}
