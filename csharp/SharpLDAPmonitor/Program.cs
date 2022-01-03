using System;
using System.Threading;
using System.Collections.Generic;
using System.Collections;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;

namespace SharpLDAPMonitor
{
    class Program
    {
        static void Main(string[] args)
        {

            var parsed = ArgumentParser.Parse(args);
            Int32 delayInSeconds = 1;
            String SearchBase = null;
            String username = null;
            String password = null;
            String connectionString = "LDAP://{0}:{1}";
            Int32 PageSize = 5000;
            DirectoryEntry ldapConnection;
            Dictionary<string, ResultPropertyCollection> results_before = null;
            Dictionary<string, ResultPropertyCollection> results_after = null;
            Logger logger = null;

            if (parsed.Arguments.ContainsKey("/logfile"))
            {
                logger = new Logger(parsed.Arguments["/logfile"], parsed.Arguments.ContainsKey("/debug"));
            }
            else
            {
                logger = new Logger(null, parsed.Arguments.ContainsKey("/debug"));
            }


            logger.WriteLine("[+]======================================================");
            logger.WriteLine("[+]  Sharp LDAP live monitor v1.3        @podalirius_    ");
            logger.WriteLine("[+]======================================================");
            logger.WriteLine("");

            // Display help
            if (parsed.Arguments.ContainsKey("/help") || parsed.Arguments.ContainsKey("/h") || parsed.Arguments.Count == 0)
            {
                logger.WriteLine("Required");
                logger.WriteLine("   /dcip:<1.1.1.1>    LDAP host to target, most likely the domain controller.");

                logger.WriteLine("\nOptional");
                logger.WriteLine("   /user:<username>   User to authenticate as.");
                logger.WriteLine("   /pass:<password>   Password of the account.");
                logger.WriteLine("   /ldaps             Use LDAPS instead of LDAP.");
                logger.WriteLine("   /searchbase        Sets the LDAP search base.");
                logger.WriteLine("   /delay:<int>       Delay between two queries in seconds (default: 1).");
                logger.WriteLine("   /randomize         Randomize delay between two queries, between 1 and 5 seconds.");
                logger.WriteLine("   /pagesize          Sets the LDAP page size to use in queries (default: 5000).");
                logger.WriteLine("   /ignoreuserlogons  Ignores user logon events.");
                logger.WriteLine("   /debug             Debug mode.");

                logger.WriteLine("\nUsage: ldapmonitor.exe /user:DOMAIN\\User /pass:MyP@ssw0rd123! /dcip:192.168.1.1");
                Environment.Exit(-1);
            }

            Boolean ignoreuserlogons = parsed.Arguments.ContainsKey("/ignoreuserlogons");

            // Time delay
            if (!(parsed.Arguments.ContainsKey("/randomize")))
            {
                if (parsed.Arguments.ContainsKey("/delay"))
                {
                    delayInSeconds = Int32.Parse(parsed.Arguments["/delay"]);
                }
                else
                {
                    delayInSeconds = 1;
                }
            }

            // Handle target host
            if (!parsed.Arguments.ContainsKey("/dcip"))
            {
                logger.WriteLine("[!] /dcip parameter is required.");
                Environment.Exit(-1);
            }

            // Handle LDAPS connection switch
            if (!parsed.Arguments.ContainsKey("/ldaps"))
            {
                connectionString = String.Format(connectionString, parsed.Arguments["/dcip"], "389");
            }
            else
            {
                connectionString = String.Format(connectionString, parsed.Arguments["/dcip"], "636");
            }

            // Handle pagesize for LDAP responses
            if (parsed.Arguments.ContainsKey("/pagesize"))
            {
                PageSize = Int32.Parse(parsed.Arguments["/pagesize"]);
            }
            else
            {
                PageSize = 5000;
            }

            // Handle 
            if (parsed.Arguments.ContainsKey("/searchbase"))
            {
                SearchBase = parsed.Arguments["/searchbase"];
            }

            // Use the provided credentials or the current session
            if (parsed.Arguments.ContainsKey("/user") && parsed.Arguments.ContainsKey("/pass"))
            {
                logger.WriteLine("[+] Using the following credentials:");
                logger.WriteLine("  | Target: " + connectionString);
                logger.WriteLine("  | User: '" + parsed.Arguments["/user"] + "'");
                logger.WriteLine("  | Pass: '" + parsed.Arguments["/pass"] + "'");
                username = parsed.Arguments["/user"];
                password = parsed.Arguments["/pass"];
            }
            else
            {
                logger.WriteLine("[+] Using the current session");
                logger.WriteLine("  | Host: " + connectionString);
            }

            try
            {
                // Get RootDSE infos (to get list of namingContexts)
                DirectoryEntry rootDSE = new System.DirectoryServices.DirectoryEntry(String.Format("{0}/RootDSE", connectionString), username, password, System.DirectoryServices.AuthenticationTypes.Secure);
                List<String> namingContexts = new List<string>();
                foreach (String nc in rootDSE.Properties["namingContexts"]) { namingContexts.Add(nc); }

                // First query 
                logger.Debug("Performing initial query ...");
                results_before = QueryAllNamingContextsOrSearchBase(namingContexts, connectionString, SearchBase, username, password, PageSize, logger);

                logger.WriteLine("\n[>] Listening for LDAP changes ...");

                while (true)
                {
                    // Update query
                    results_after = QueryAllNamingContextsOrSearchBase(namingContexts, connectionString, SearchBase, username, password, PageSize, logger);

                    // Diff
                    diff(results_before, results_after, connectionString, logger, ignoreuserlogons);
                    results_before = results_after;

                    logger.Debug("Waiting " + delayInSeconds + " second.");

                    if (parsed.Arguments.ContainsKey("/randomize"))
                    {
                        Random rnd = new Random();
                        delayInSeconds = rnd.Next(1, 5);
                    }
                    Thread.Sleep(delayInSeconds * 1000);
                }
            }
            catch (System.Runtime.InteropServices.COMException e)
            {
                logger.WriteLine("\n");
                logger.Warning("Error: (0x" + e.ErrorCode.ToString("X8") + ") " + e.Message);
            }
        }

        static Dictionary<string, ResultPropertyCollection> QueryAllNamingContextsOrSearchBase(List<String> namingContexts, String connectionString, String SearchBase, String Username, String Password, int PageSize, Logger logger)
        {
            DirectoryEntry ldapConnection;
            DirectorySearcher ldapSearcher;
            Dictionary<string, ResultPropertyCollection> results = new Dictionary<string, ResultPropertyCollection>();

            if (SearchBase != null)
            {
                logger.Debug(String.Format("Using SearchBase: {0}", SearchBase));
                ldapConnection = new System.DirectoryServices.DirectoryEntry(String.Format("{0}/{1}", connectionString, SearchBase), Username, Password, System.DirectoryServices.AuthenticationTypes.Secure);
                ldapSearcher = new DirectorySearcher(ldapConnection);
                ldapSearcher.Filter = "(objectClass=*)";

                foreach (SearchResult item in ldapSearcher.FindAll())
                {
                    if (!(results.ContainsKey(item.Path)))
                    {
                        results[item.Path] = item.Properties;
                    }
                    else
                    {
                        logger.Debug(String.Format("[debug] key already exists: {0} (this shouldn't be possible)", item.Path));
                    }
                }

                return results;
            }
            else
            {
                foreach (String nc in namingContexts) {
                    logger.Debug(String.Format("Using namingContext as search base: {0}", SearchBase));
                    ldapConnection = new System.DirectoryServices.DirectoryEntry(String.Format("{0}/{1}", connectionString, nc), Username, Password, System.DirectoryServices.AuthenticationTypes.Secure);
                    ldapSearcher = new DirectorySearcher(ldapConnection);
                    ldapSearcher.Filter = "(objectClass=*)";

                    foreach(SearchResult item in ldapSearcher.FindAll()) {
                        if (!(results.ContainsKey(item.Path)))
                        {
                            results[item.Path] = item.Properties;
                        }
                        else
                        {
                            logger.Debug(String.Format("[debug] key already exists: {0} (this shouldn't be possible)", item.Path));
                        }
                    }
                }
                return results;
            }
        }

        /*        static void InitLdapConnection()
                {
                     = new DirectoryEntry(connectionString, username, password, System.DirectoryServices.AuthenticationTypes.Secure);
                    logger.Debug("Authentication successful!");
                }
        */
        static void diff(Dictionary<string, ResultPropertyCollection> dict_results_before, Dictionary<string, ResultPropertyCollection> dict_results_after, String connectionString, Logger logger, Boolean ignoreuserlogons)
        {
            List<String> ignore_keys = new List<String>();
            if (ignoreuserlogons)
            {
                ignore_keys.Add("lastlogon");
                ignore_keys.Add("logoncount");
            }

            String dateprompt = "[" + DateTime.UtcNow.ToString("yyyy/MM/dd hh:mm:ss") + "] ";
 
            // Get created and deleted entries, and common_keys
            List<String> common_keys = new List<String>();
            foreach (String key in dict_results_before.Keys)
            {
                if (dict_results_after.ContainsKey(key)) { common_keys.Add(key); }
                else { logger.WriteLine(dateprompt + "'" + key.Replace(connectionString + "/", "") + "' was deleted."); }
            }
            foreach (String key in dict_results_after.Keys)
            {
                if (!dict_results_before.ContainsKey(key)) { logger.WriteLine(dateprompt + "'" + key.Replace(connectionString + "/", "") + "' was added."); }
            }

            List<Tuple<string, string, Object, Object>> attrs_diff = new List<Tuple<string, string, Object, Object>>();

            // Iterate over all the common keys
            foreach (String path in common_keys)
            {
                attrs_diff.Clear();

                // Convert into dictionnaries
                Dictionary<String, Object> dict_direntry_before = new Dictionary<String, Object>();
                Dictionary<String, Object> dict_direntry_after = new Dictionary<String, Object>();

                foreach (DictionaryEntry prop in dict_results_before[path])
                {
                    if (!(ignore_keys.Contains(prop.Key.ToString().ToLower())))
                    {
                        dict_direntry_before.Add(prop.Key.ToString(), dict_results_before[path][prop.Key.ToString()][0]);
                    }
                };
                foreach (DictionaryEntry prop in dict_results_after[path])
                {
                    if (!(ignore_keys.Contains(prop.Key.ToString().ToLower())))
                    {
                        dict_direntry_after.Add(prop.Key.ToString(), dict_results_after[path][prop.Key.ToString()][0]);
                    }
                };

                // Store different values
                foreach (String pname in dict_direntry_after.Keys)
                {
                    if (dict_direntry_after.ContainsKey(pname) && dict_direntry_before.ContainsKey(pname))
                    {
                        if (!(dict_direntry_after[pname].ToString() == dict_direntry_before[pname].ToString()))
                        {
                            Tuple<string, string, Object, Object> diff = new Tuple<string, string, Object, Object>(path, pname, dict_direntry_after[pname], dict_direntry_before[pname]);
                            attrs_diff.Add(diff);
                        }
                    }
                    else if (dict_direntry_after.ContainsKey(pname) && !dict_direntry_before.ContainsKey(pname))
                    {
                        Tuple<string, string, Object, Object> diff = new Tuple<string, string, Object, Object>(path, pname, dict_direntry_after[pname], null);
                        attrs_diff.Add(diff);
                    }
                    else if (!dict_direntry_after.ContainsKey(pname) && dict_direntry_before.ContainsKey(pname))
                    {
                        Tuple<string, string, Object, Object> diff = new Tuple<string, string, Object, Object>(path, pname, null, dict_direntry_before[pname]);
                        attrs_diff.Add(diff);
                    }
                }

                // Show results
                if (attrs_diff.ToArray().Length != 0)
                {
                    logger.WriteLine(dateprompt + path.Replace(connectionString + "/", ""));

                    foreach (Tuple<string, string, Object, Object> t in attrs_diff)
                    {
                        if ((t.Item4 != null) && (t.Item3 != null))
                        {
                            logger.WriteLine(" | Attribute " + t.Item2 + " changed from '" + t.Item4 + "' to '" + t.Item3 + "'");
                        }
                        else if ((t.Item4 == null) && (t.Item3 != null))
                        {
                            logger.WriteLine(" | Attribute " + t.Item2 + " = '" + t.Item3 + "' was created.");
                        }
                        else if ((t.Item4 != null) && (t.Item3 == null))
                        {
                            logger.WriteLine(" | Attribute " + t.Item2 + " = '" + t.Item4 + "' was deleted.");
                        }
                    }
                }
            }
        }
    }
}
