using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Windows.Forms;
using HaveIBeenPwned.BreachCheckers;
using HaveIBeenPwned.BreachCheckers.HaveIBeenPwnedPassword;
using HaveIBeenPwned.BreachCheckers.HaveIBeenPwnedSite;
using HaveIBeenPwned.BreachCheckers.HaveIBeenPwnedUsername;
using HaveIBeenPwned.UI;
using KeePass.Forms;
using KeePass.Plugins;
using KeePassExtensions;
using KeePassLib;

namespace HaveIBeenPwned
{
    public sealed class HaveIBeenPwnedExt : Plugin
    {
        private IPluginHost pluginHost;
        private HttpClient client;
        private StatusProgressForm progressForm;
        private bool isTerminating;
        private bool isChecking;

        private readonly Dictionary<BreachEnum, Func<HttpClient, IPluginHost, BaseChecker>> supportedBreachCheckers =
            new Dictionary<BreachEnum, Func<HttpClient, IPluginHost, BaseChecker>>
            {
                { BreachEnum.HIBPSite, (h, p) => new HaveIBeenPwnedSiteChecker(h, p) },
                { BreachEnum.HIBPUsername, (h, p) => new HaveIBeenPwnedUsernameChecker(h, p) },
                { BreachEnum.HIBPPassword, (h, p) => new HaveIBeenPwnedPasswordChecker(h, p) },
                { BreachEnum.CheckAll, (h, p) => new CombinedChecker(h, p) }
            };


        public override bool Initialize(IPluginHost host)
        {
            if (host == null) return false;

            pluginHost = host;
            isTerminating = false;
            isChecking = false;

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

            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            client.DefaultRequestHeaders.UserAgent.ParseAdd(string.Format("KeePass HIBP Checker/{0}", System.Reflection.Assembly.GetExecutingAssembly().GetName().Version));
            client.Timeout = new TimeSpan(0, 30, 0);

            return true;
        }

        public override void Terminate()
        {
            isTerminating = true;

            if (progressForm != null && !progressForm.IsDisposed)
            {
                progressForm.Close();
            }

            if (client != null)
            {
                client.Dispose();
            }
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
            if (isTerminating || progressForm == null || progressForm.IsDisposed) return;

            var progressHelper = progressForm.Tag as ProgressHelper;
            if (progressHelper == null || progressHelper.TotalBreaches <= 0) return;

            var currentProgress = ((100f * progressHelper.CurrentBreach) + progress.Progress) / progressHelper.TotalBreaches;
            progressForm.SetProgress((uint)Math.Min(100f, currentProgress));
            progressForm.SetText(progress.ProgressText, KeePassLib.Interfaces.LogStatusType.Info);
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
            if (isTerminating || isChecking || group == null) return;
            isChecking = true;
            StatusProgressForm currentProgressForm = null;

            try
            {
                using (var prompt = new CheckerPrompt(breachType, breachType != CheckTypeEnum.Password))
                {
                    if (prompt.ShowDialog(pluginHost.MainWindow) != DialogResult.OK) return;

                    var selectedBreaches = prompt.CheckAllBreaches
                        ? Enum.GetValues(typeof(BreachEnum)).Cast<BreachEnum>()
                            .Where(b => b.GetAttribute<CheckerTypeAttribute>().Type == breachType)
                            .ToArray()
                        : new[] { prompt.SelectedBreach };
                    if (selectedBreaches.Length == 0) return;

                    currentProgressForm = new StatusProgressForm();
                    progressForm = currentProgressForm;
                    currentProgressForm.Tag = new ProgressHelper(selectedBreaches.Length);
                    currentProgressForm.InitEx("Checking Breaches", true, breachType == CheckTypeEnum.SiteDomain, pluginHost.MainWindow);
                    currentProgressForm.Show();
                    currentProgressForm.SetProgress(0);

                    var progressIndicator = new Progress<ProgressItem>(ReportProgress);
                    Func<bool> canContinue = () => !isTerminating && !currentProgressForm.IsDisposed && currentProgressForm.ContinueWork();
                    List<BreachedEntry> result = new List<BreachedEntry>();

                    try
                    {
                        foreach (var breach in selectedBreaches)
                        {
                            if (!canContinue()) break;

                            var checker = supportedBreachCheckers[breach](client, pluginHost);
                            var foundBreaches = await checker.CheckGroup(
                                group,
                                prompt.ExpireEntries,
                                prompt.OnlyCheckOldEntries,
                                prompt.IgnoreDeletedEntries,
                                prompt.IgnoreExpiredEntries,
                                progressIndicator,
                                canContinue);
                            result.AddRange(foundBreaches);
                            ((ProgressHelper)currentProgressForm.Tag).CurrentBreach++;
                        }
                    }
                    catch (Exception ex)
                    {
                        result = null;
                        if (!isTerminating)
                        {
                            MessageBox.Show(pluginHost.MainWindow, ex.Message, Resources.MessageTitle, MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }

                    if (isTerminating || !canContinue() || result == null) return;

                    if (result.Count == 0)
                    {
                        MessageBox.Show(pluginHost.MainWindow, "No breached entries found.", Resources.MessageTitle, MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    else
                    {
                        using (var breachedEntriesDialog = new BreachedEntriesDialog(pluginHost))
                        {
                            breachedEntriesDialog.AddBreaches(result);
                            breachedEntriesDialog.ShowDialog(pluginHost.MainWindow);
                        }
                    }
                }
            }
            finally
            {
                if (currentProgressForm != null && !currentProgressForm.IsDisposed)
                {
                    currentProgressForm.Close();
                }

                if (ReferenceEquals(progressForm, currentProgressForm)) progressForm = null;
                isChecking = false;
                if (!isTerminating && pluginHost != null) pluginHost.MainWindow.Show();
            }
        }

        private bool AssertDatabaseOpen()
        {
            if (isTerminating || pluginHost == null) return false;
            if (!pluginHost.Database.IsOpen)
            {
                MessageBox.Show("You must first open a database", Resources.MessageTitle, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            return true;
        }
    }
}
