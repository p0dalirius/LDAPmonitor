using System;
using System.IO;

namespace SharpLDAPMonitor
{
    public class Logger
    {
        Boolean debug = false;
        String logfile = null;

        public Logger(String logfile=null, Boolean debug=false)
        {
            this.logfile = logfile;
            this.debug = debug;
            if (this.logfile != null)
            {
                // Init logfile (overwrite)
                using (FileStream aFile = new FileStream(this.logfile, FileMode.Create, FileAccess.Write)) { }
            }
        }

        public void Debug(String message)
        {
            if (this.debug == true)
            {
                Console.WriteLine("[debug] "+message);
                if (this.logfile != null)
                {
                    using (FileStream aFile = new FileStream(this.logfile, FileMode.Append, FileAccess.Write))
                    using (StreamWriter sw = new StreamWriter(aFile))
                    {
                        sw.WriteLine("[debug] " + message);
                    }
                }
            }
        }

        public void WriteLine(String message)
        {
            Console.WriteLine(message);
            if (this.logfile != null)
            {
                using (FileStream aFile = new FileStream(this.logfile, FileMode.Append, FileAccess.Write))
                using (StreamWriter sw = new StreamWriter(aFile))
                {
                    sw.WriteLine(message);
                }
            }
        }

        public void Warning(String message)
        {
            Console.WriteLine("[!] " + message);
            if (this.logfile != null)
            {
                using (FileStream aFile = new FileStream(this.logfile, FileMode.Append, FileAccess.Write))
                using (StreamWriter sw = new StreamWriter(aFile))
                {
                    sw.WriteLine("[!] " + message);
                }
            }
        }
    }
}
