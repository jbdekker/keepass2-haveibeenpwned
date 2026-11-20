using System;
using KeePassLib;
using System.Net.Http;
using KeePass.Plugins;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace HaveIBeenPwned.BreachCheckers
{
    public abstract class BaseChecker
    {
        protected readonly HttpClient client;
        protected readonly IPluginHost pluginHost;

        protected BaseChecker(HttpClient httpClient, IPluginHost pluginHost)
        {
            client = httpClient;
            this.pluginHost = pluginHost;
        }

        public abstract Task<List<BreachedEntry>> CheckGroup(
            PwGroup group,
            bool expireEntries,
            bool oldEntriesOnly,
            bool ignoreDeleted,
            bool ignoreExpired,
            IProgress<ProgressItem> progressIndicator,
            Func<bool> canContinue);

        protected void ExpireEntry(PwEntry entry)
        {
            entry.Expires = true;
            entry.ExpiryTime = DateTime.Now;
        }
    }
}
