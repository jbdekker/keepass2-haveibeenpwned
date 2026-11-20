using System;

namespace HaveIBeenPwned.BreachCheckers
{
    public sealed class HaveIBeenPwnedEntry : IBreach
    {
        public string Title { get; set; }
        public DateTime BreachDate { get; set; }
        public string[] DataClasses { get; set; }
        public string Domain { get; set; }
        public string Username { get; set; }
        public string Description { get; set; }
    }
}
