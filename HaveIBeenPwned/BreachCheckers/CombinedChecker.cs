using System;
using System.Collections.Generic;
using KeePassLib;
using System.Net.Http;
using KeePass.Plugins;
using System.Threading.Tasks;

namespace HaveIBeenPwned.BreachCheckers
{
    public class CombinedChecker : BaseChecker
    {
        private readonly BaseChecker[] checkers;

        public CombinedChecker(HttpClient httpClient, IPluginHost pluginHost)
            : base(httpClient, pluginHost)
        {
            checkers = new BaseChecker[]
            {
                new HaveIBeenPwnedSite.HaveIBeenPwnedSiteChecker(httpClient, pluginHost),
                new HaveIBeenPwnedPassword.HaveIBeenPwnedPasswordChecker(httpClient, pluginHost),
                new HaveIBeenPwnedUsername.HaveIBeenPwnedUsernameChecker(httpClient, pluginHost)
            };
        }

        public override async Task<List<BreachedEntry>> CheckGroup(PwGroup group, bool expireEntries, bool oldEntriesOnly, bool ignoreDeleted, bool ignoreExpired, IProgress<ProgressItem> progressIndicator, Func<bool> canContinue)
        {
            var results = new List<BreachedEntry>();

            foreach (var checker in checkers)
            {
                if (!canContinue()) break;

                var checkerResults = await checker.CheckGroup(group, expireEntries, oldEntriesOnly, ignoreDeleted, ignoreExpired, progressIndicator, canContinue);
                results.AddRange(checkerResults);
            }

            return results;
        }
    }
}
