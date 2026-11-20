using KeePassLib;
using System;

namespace HaveIBeenPwned.BreachCheckers
{
    public class BreachedEntry
    {
        private readonly IBreach breach;
        private static readonly string[] EmptyDataClasses = new string[0];

        public PwEntry Entry { get; private set; }

        public DateTime BreachDate
        {
            get
            {
                return breach.BreachDate;
            }
        }

        public string BreachName
        {
            get
            {
                return breach.Title;
            }
        }

        public string BreachUrl
        {
            get
            {
                return breach.Domain;
            }
        }

        public string BreachUsername
        {
            get
            {
                return breach.Username;
            }
        }

        public string Description
        {
            get
            {
                return breach.Description;
            }
        }
        
        public string[] DataClasses
        {
            get
            {
                return breach.DataClasses ?? EmptyDataClasses;
            }
        }

        public BreachedEntry(PwEntry entry, IBreach breach)
        {
            Entry = entry;
            this.breach = breach;
        }
    }
}
