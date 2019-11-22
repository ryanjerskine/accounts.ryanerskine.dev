using DbUp;
using System;
using System.Linq;
using System.Reflection;

namespace Accounts.RyanErskine.Dev.DbUp
{
    public class Program
    {
        public static int Main(string[] args)
        {
            var connectionString = args.FirstOrDefault() ?? "Server=(localdb)\\ProjectsV13; Database=IdentityServer; Trusted_connection=true";

            if (!args.Any())
                EnsureDatabase.For.SqlDatabase(connectionString, 0);

            var upgrader = DeployChanges.To
                .SqlDatabase(connectionString)
                .WithScriptsAndCodeEmbeddedInAssembly(Assembly.GetExecutingAssembly())
                .JournalToSqlTable("dbo", "__DbUpSchemaVersions")
                .LogToConsole()
                .LogScriptOutput()
                .Build();

            if (!upgrader.IsUpgradeRequired())
                return 0;

            var result = upgrader.PerformUpgrade();
            if (result.Successful)
                return 0;

            Console.WriteLine(result.Error);
#if DEBUG
            Console.ReadLine();
#endif
            return -1;
        }
    }
}
