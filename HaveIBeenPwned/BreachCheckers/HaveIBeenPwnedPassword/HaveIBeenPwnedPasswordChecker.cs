using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using HaveIBeenPwned.BreachCheckers;
using KeePassExtensions;
using KeePass.Plugins;
using KeePassLib;
using KeePassLib.Utility;

namespace HaveIBeenPwned.BreachCheckers.HaveIBeenPwnedPassword
{
    public class HaveIBeenPwnedPasswordChecker : BaseChecker
    {
        private const string ApiUrl = "https://api.pwnedpasswords.com/range/{0}";
        private const string HexDigits = "0123456789ABCDEF";

        public HaveIBeenPwnedPasswordChecker(HttpClient httpClient, IPluginHost pluginHost)
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
            progressIndicator.Report(new ProgressItem(0, "Checking passwords with Have I Been Pwned..."));
            var entries = group.GetEntries(true)
                .Where(e => (!ignoreDeleted || !e.IsDeleted(pluginHost)) && (!ignoreExpired || !e.Expires))
                .ToArray();
            var breaches = await GetBreaches(progressIndicator, entries, canContinue);
            var breachedEntries = new List<BreachedEntry>();

            foreach (var breach in breaches)
            {
                if (!canContinue()) break;

                if (breach.Entry != null && expireEntries) ExpireEntry(breach.Entry);
                breachedEntries.Add(new BreachedEntry(breach.Entry, breach));
            }

            return breachedEntries;
        }

        private async Task<List<HaveIBeenPwnedPasswordEntry>> GetBreaches(
            IProgress<ProgressItem> progressIndicator,
            PwEntry[] entries,
            Func<bool> canContinue)
        {
            var allBreaches = new List<HaveIBeenPwnedPasswordEntry>();
            var cache = new Dictionary<string, bool>();

            using (var sha = SHA1.Create())
            {
                for (var i = 0; i < entries.Length; i++)
                {
                    if (!canContinue()) break;

                    var entry = entries[i];
                    var password = entry.Strings.Get(PwDefs.PasswordField);
                    if (password == null)
                    {
                        ReportProgress(progressIndicator, entry, i, entries.Length);
                        continue;
                    }

                    var passwordBytes = password.ReadUtf8();
                    try
                    {
                        if (IsBlankOrReference(passwordBytes))
                        {
                            ReportProgress(progressIndicator, entry, i, entries.Length);
                            continue;
                        }

                        var hashBytes = sha.ComputeHash(passwordBytes);
                        string passwordHash;
                        try
                        {
                            passwordHash = ToHexString(hashBytes);
                        }
                        finally
                        {
                            MemUtil.ZeroByteArray(hashBytes);
                        }

                        bool isBreached;
                        if (cache.TryGetValue(passwordHash, out isBreached))
                        {
                            if (isBreached) allBreaches.Add(CreateBreach(entry));
                            ReportProgress(progressIndicator, entry, i, entries.Length);
                            continue;
                        }

                        var prefix = passwordHash.Substring(0, 5);
                        var suffix = passwordHash.Substring(5);
                        var found = await CheckPasswordRange(prefix, suffix, canContinue);
                        cache.Add(passwordHash, found);
                        if (found) allBreaches.Add(CreateBreach(entry));
                        ReportProgress(progressIndicator, entry, i, entries.Length);
                    }
                    finally
                    {
                        MemUtil.ZeroByteArray(passwordBytes);
                    }
                }
            }

            return allBreaches;
        }

        private async Task<bool> CheckPasswordRange(string prefix, string suffix, Func<bool> canContinue)
        {
            using (var request = new HttpRequestMessage(HttpMethod.Get, string.Format(CultureInfo.InvariantCulture, ApiUrl, prefix)))
            {
                request.Headers.Add("Add-Padding", "true");

                using (var response = await client.SendAsync(request))
                {
                    response.EnsureSuccessStatusCode();
                    var stream = await response.Content.ReadAsStreamAsync();
                    using (var reader = new StreamReader(stream, Encoding.ASCII))
                    {
                        string line;
                        while (canContinue() && (line = await reader.ReadLineAsync()) != null)
                        {
                            var separator = line.IndexOf(':');
                            int count;
                            if (separator <= 0 || !int.TryParse(line.Substring(separator + 1), NumberStyles.None, CultureInfo.InvariantCulture, out count))
                            {
                                throw new InvalidDataException("HIBP returned an invalid password range response.");
                            }

                            if (count > 0 && string.Equals(line.Substring(0, separator), suffix, StringComparison.OrdinalIgnoreCase))
                            {
                                return true;
                            }
                        }
                    }
                }
            }

            return false;
        }

        private static HaveIBeenPwnedPasswordEntry CreateBreach(PwEntry entry)
        {
            return new HaveIBeenPwnedPasswordEntry(
                entry.Strings.ReadSafe(PwDefs.UserNameField),
                entry.GetUrlDomain(),
                entry);
        }

        private static void ReportProgress(IProgress<ProgressItem> progressIndicator, PwEntry entry, int index, int total)
        {
            var progress = total == 0 ? 100U : (uint)(((index + 1) * 100) / total);
            progressIndicator.Report(new ProgressItem(progress, string.Format("Checking \"{0}\" for breaches", entry.Strings.ReadSafe(PwDefs.TitleField))));
        }

        private static bool IsBlankOrReference(byte[] passwordBytes)
        {
            var characters = Encoding.UTF8.GetChars(passwordBytes);
            try
            {
                var blank = true;
                for (var i = 0; i < characters.Length; i++)
                {
                    if (!char.IsWhiteSpace(characters[i]))
                    {
                        blank = false;
                        break;
                    }
                }

                if (blank) return true;
                return characters.Length >= 5 && characters[0] == '{' &&
                    (characters[1] == 'R' || characters[1] == 'r') &&
                    (characters[2] == 'E' || characters[2] == 'e') &&
                    (characters[3] == 'F' || characters[3] == 'f') && characters[4] == ':';
            }
            finally
            {
                Array.Clear(characters, 0, characters.Length);
            }
        }

        private static string ToHexString(byte[] bytes)
        {
            var characters = new char[bytes.Length * 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                characters[i * 2] = HexDigits[bytes[i] >> 4];
                characters[i * 2 + 1] = HexDigits[bytes[i] & 15];
            }

            return new string(characters);
        }
    }
}
