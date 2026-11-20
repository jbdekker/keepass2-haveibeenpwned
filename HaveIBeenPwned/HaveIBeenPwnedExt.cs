using System.Windows.Forms;
using KeePass.Plugins;
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeePass.Forms;
using HaveIBeenPwned.BreachCheckers;
using HaveIBeenPwned.BreachCheckers.HaveIBeenPwnedSite;
using HaveIBeenPwned.BreachCheckers.CloudbleedSite;
using HaveIBeenPwned.BreachCheckers.HaveIBeenPwnedUsername;
using HaveIBeenPwned.BreachCheckers.HaveIBeenPwnedPassword;
using HaveIBeenPwned.UI;

using KeePassLib;
using System.Text;
using KeePassExtensions;

namespace HaveIBeenPwned
{
    public sealed class HaveIBeenPwnedExt : Plugin
    {
        private IPluginHost pluginHost;

        private HttpClient client;
        private StatusProgressForm progressForm;

        private Dictionary<BreachEnum, Func<HttpClient, IPluginHost, BaseChecker>> supportedBreachCheckers =
            new Dictionary<BreachEnum, Func<HttpClient, IPluginHost, BaseChecker>>
        {
            { BreachEnum.HIBPSite, (h,p) => new HaveIBeenPwnedSiteChecker(h, p) },
            { BreachEnum.CloudBleedSite, (h,p) => new CloudbleedSiteChecker(h, p) },
            { BreachEnum.HIBPUsername, (h, p) => new HaveIBeenPwnedUsernameChecker(h, p) },
            { BreachEnum.HIBPPassword, (h, p) => new HaveIBeenPwnedPasswordChecker(h, p) },
            { BreachEnum.CheckAll, (h, p) => new CombinedChecker(h, p) }
        };

        public override bool Initialize(IPluginHost host)
        {
            if (host == null) return false;

            pluginHost = host;

            // Use the KeePass proxy configuration for all HIBP requests.
            var proxyType = KeePass.Program.Config.Integration.ProxyType;
            var proxyAddress = KeePass.Program.Config.Integration.ProxyAddress;
            var proxyPort = KeePass.Program.Config.Integration.ProxyPort;
            var proxyAuth = KeePass.Program.Config.Integration.ProxyAuthType;
            var proxyUsername = KeePass.Program.Config.Integration.ProxyUserName;
            var proxyPassword = KeePass.Program.Config.Integration.ProxyPassword;

            if (proxyType == ProxyServerType.Manual)
            {
                HttpClientHandler handler;
                if (proxyAuth == ProxyAuthType.Manual)
                {
                    handler = new HttpClientHandler
                    {
                        Proxy = new WebProxy(String.Format("{0}:{1}", proxyAddress, proxyPort), false, null, new NetworkCredential(proxyUsername, proxyPassword)),
                        UseProxy = true,
                    };
                }
                else
                {
                    handler = new HttpClientHandler
                    {
                        Proxy = new WebProxy(String.Format("{0}:{1}", proxyAddress, proxyPort)),
                        UseProxy = true,
                    };
                }

                client = new HttpClient(handler);
            }
            else
            {
                client = new HttpClient();
            }

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            client.DefaultRequestHeaders.UserAgent.ParseAdd(string.Format("KeePass HIBP Checker/{0}", System.Reflection.Assembly.GetExecutingAssembly().GetName().Version));
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            client.Timeout = new TimeSpan(0, 30, 0);

            return true;
        }

        public override void Terminate()
        {
            if (client != null)
            {
                client.Dispose();
                client = null;
            }

            pluginHost = null;
        }

        public override ToolStripMenuItem GetMenuItem(PluginMenuType t)
        {
            switch (t)
            {
                case PluginMenuType.Main:
                    return CreateCheckerMenuItem(
                        this.Database_CheckHaveIBeenPwnedSites,
                        this.Database_CheckHaveIBeenPwnedUsernames,
                        this.Database_CheckHaveIBeenPwnedPasswords,
                        this.Database_CheckAll);
                case PluginMenuType.Group:
                    return CreateCheckerMenuItem(
                        this.Group_CheckHaveIBeenPwnedSites,
                        this.Group_CheckHaveIBeenPwnedUsernames,
                        this.Group_CheckHaveIBeenPwnedPasswords,
                        this.Group_CheckAll);
                case PluginMenuType.Entry:
                    return CreateCheckerMenuItem(
                        this.Entries_CheckHaveIBeenPwnedSites,
                        this.Entries_CheckHaveIBeenPwnedUsernames,
                        this.Entries_CheckHaveIBeenPwnedPasswords,
                        this.Entries_CheckAll);
                default:
                    return null;
            }
        }

        private ToolStripMenuItem CreateCheckerMenuItem(
            EventHandler checkSites,
            EventHandler checkUsernames,
            EventHandler checkPasswords,
            EventHandler checkAll)
        {
            var menuItem = new ToolStripMenuItem
            {
                Text = Resources.MenuTitle,
                Image = Resources.hibp.ToBitmap()
            };

            AddCheckerMenuItem(menuItem, Resources.MenuItemSiteTitle, checkSites);
            AddCheckerMenuItem(menuItem, Resources.MenuItemUsernameTitle, checkUsernames);
            AddCheckerMenuItem(menuItem, Resources.MenuItemPasswordTitle, checkPasswords);
            AddCheckerMenuItem(menuItem, Resources.MenuItemCheckAllTitle, checkAll);

            return menuItem;
        }

        private static void AddCheckerMenuItem(ToolStripMenuItem parent, string text, EventHandler clickHandler)
        {
            var menuItem = new ToolStripMenuItem
            {
                Text = text,
                Image = Resources.hibp.ToBitmap()
            };
            menuItem.Click += clickHandler;
            parent.DropDownItems.Add(menuItem);
        }


        public override string UpdateUrl
        {
            get
            {
                return "https://raw.githubusercontent.com/jbdekker/keepass2-haveibeenpwned/main/VERSION";
            }
        }

        public override Image SmallIcon
        {
            get
            {
                return Resources.hibp.ToBitmap();
            }
        }


        private void ReportProgress(ProgressItem progress)
        {
            if (progressForm != null && !progressForm.IsDisposed)
            {
                var progressHelper = (ProgressHelper)progressForm.Tag;
                var currentProgress = ((100f / progressHelper.TotalBreaches) * progressHelper.CurrentBreach) + (progress.Progress / progressHelper.TotalBreaches);
                progressForm.SetProgress((uint)currentProgress);
                progressForm.SetText(progress.ProgressText, KeePassLib.Interfaces.LogStatusType.Info);
            }
        }

        private async void Database_CheckHaveIBeenPwnedSites(object sender, EventArgs e)
        {
            if (!AssertDatabaseOpen()) return;
            await CheckBreach(CheckTypeEnum.SiteDomain, pluginHost.Database.RootGroup);
        }

        private async void Database_CheckHaveIBeenPwnedUsernames(object sender, EventArgs e)
        {
            if (!AssertDatabaseOpen()) return;
            await CheckBreach(CheckTypeEnum.Username, pluginHost.Database.RootGroup);
        }

        private async void Database_CheckHaveIBeenPwnedPasswords(object sender, EventArgs e)
        {
            if (!AssertDatabaseOpen()) return;
            await CheckBreach(CheckTypeEnum.Password, pluginHost.Database.RootGroup);
        }

        private async void Database_CheckAll(object sender, EventArgs e)
        {
            if (!AssertDatabaseOpen()) return;
            await CheckBreach(CheckTypeEnum.CheckAll, pluginHost.Database.RootGroup);
        }

        private async void Group_CheckHaveIBeenPwnedSites(object sender, EventArgs e)
        {
            if (!AssertDatabaseOpen()) return;
            await CheckBreach(CheckTypeEnum.SiteDomain, pluginHost.MainWindow.GetSelectedGroup());
        }

        private async void Group_CheckHaveIBeenPwnedUsernames(object sender, EventArgs e)
        {
            if (!AssertDatabaseOpen()) return;
            await CheckBreach(CheckTypeEnum.Username, pluginHost.MainWindow.GetSelectedGroup());
        }

        private async void Group_CheckHaveIBeenPwnedPasswords(object sender, EventArgs e)
        {
            if (!AssertDatabaseOpen()) return;
            await CheckBreach(CheckTypeEnum.Password, pluginHost.MainWindow.GetSelectedGroup());
        }

        private async void Group_CheckAll(object sender, EventArgs e)
        {
            if (!AssertDatabaseOpen()) return;
            await CheckBreach(CheckTypeEnum.CheckAll, pluginHost.MainWindow.GetSelectedGroup());
        }

        private async void Entries_CheckHaveIBeenPwnedSites(object sender, EventArgs e)
        {
            if (!AssertDatabaseOpen()) return;
            await CheckBreach(CheckTypeEnum.SiteDomain, pluginHost.MainWindow.GetSelectedEntriesAsGroup());
        }

        private async void Entries_CheckHaveIBeenPwnedUsernames(object sender, EventArgs e)
        {
            if (!AssertDatabaseOpen()) return;
            await CheckBreach(CheckTypeEnum.Username, pluginHost.MainWindow.GetSelectedEntriesAsGroup());
        }

        private async void Entries_CheckHaveIBeenPwnedPasswords(object sender, EventArgs e)
        {
            if (!AssertDatabaseOpen()) return;
            await CheckBreach(CheckTypeEnum.Password, pluginHost.MainWindow.GetSelectedEntriesAsGroup());
        }

        private async void Entries_CheckAll(object sender, EventArgs e)
        {
            if (!AssertDatabaseOpen()) return;
            await CheckBreach(CheckTypeEnum.CheckAll, pluginHost.MainWindow.GetSelectedEntriesAsGroup());
        }

        private async Task CheckBreach(CheckTypeEnum breachType, PwGroup group)
        {
            var dialog = new CheckerPrompt(breachType, breachType != CheckTypeEnum.Password);

            if (dialog.ShowDialog() == DialogResult.OK)
            {
                progressForm = new StatusProgressForm();
                var progressIndicator = new Progress<ProgressItem>(ReportProgress);
                progressForm.InitEx("Checking Breaches", true, breachType == CheckTypeEnum.SiteDomain, pluginHost.MainWindow);
                progressForm.Show();
                progressForm.SetProgress(0);
                List<BreachedEntry> result = new List<BreachedEntry>();
                try
                {
                    if (dialog.CheckAllBreaches)
                    {
                        var breaches = Enum.GetValues(typeof(BreachEnum)).Cast<BreachEnum>().Where(b => b.GetAttribute<CheckerTypeAttribute>().Type == breachType);
                        progressForm.Tag = new ProgressHelper(breaches.Count());
                        foreach (var breach in breaches)
                        {
                            var foundBreaches = await CheckBreaches(supportedBreachCheckers[(BreachEnum)breach](client, pluginHost),
                            group, dialog.ExpireEntries, dialog.OnlyCheckOldEntries, dialog.IgnoreDeletedEntries, dialog.IgnoreExpiredEntries, progressIndicator, () => progressForm.ContinueWork());
                            result.AddRange(foundBreaches);
                            ((ProgressHelper)progressForm.Tag).CurrentBreach++;
                        }
                    }
                    else
                    {
                        progressForm.Tag = new ProgressHelper(1);
                        var foundBreaches = await CheckBreaches(supportedBreachCheckers[dialog.SelectedBreach](client, pluginHost),
                            group, dialog.ExpireEntries, dialog.OnlyCheckOldEntries, dialog.IgnoreDeletedEntries, dialog.IgnoreExpiredEntries, progressIndicator, () => progressForm.ContinueWork());
                        result.AddRange(foundBreaches);
                    }
                }
                catch (Exception ex)
                {
                    result = null;
                    MessageBox.Show(pluginHost.MainWindow, ex.Message, Resources.MessageTitle, MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                finally
                {
                    progressForm.Close();
                }

                if (result != null)
                {
                    if (!result.Any())
                    {
                        MessageBox.Show(pluginHost.MainWindow, "No breached entries found.", Resources.MessageTitle, MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    else
                    {
                        var breachedEntriesDialog = new BreachedEntriesDialog(pluginHost);
                        breachedEntriesDialog.AddBreaches(result);
                        breachedEntriesDialog.ShowDialog();
                    }
                }
            }

            pluginHost.MainWindow.Show();
        }

        private async Task<IList<BreachedEntry>> CheckBreaches(
            BaseChecker breachChecker,
            PwGroup group,
            bool expireEntries,
            bool oldEntriesOnly,
            bool ignoreDeleted,
            bool ignoreExpired,
            IProgress<ProgressItem> progressIndicator,
            Func<bool> canContinue)
        {
           return await breachChecker.CheckGroup(group, expireEntries, oldEntriesOnly, ignoreDeleted, ignoreExpired, progressIndicator, canContinue);
        }

        private bool AssertDatabaseOpen()
        {
            if (!pluginHost.Database.IsOpen)
            {
                MessageBox.Show("You must first open a database", Resources.MessageTitle, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
            return true;
        }
    }
}
