# Sharp LDAP Monitor

Monitor creation, deletion and changes to LDAP objects live during your pentest or system administration!

With this script you can quickly see if your attack worked and if it changed LDAP attributes of the target object. You can also directly see if you're locking accounts!

![](./imgs/example.png)

## Features

 - [x] LDAPS support.
 - [x] Random delay in seconds between queries.
 - [x] Custom delay in seconds between queries.
 - [x] Save output to logfile.
 - [x] Custom page size for paged queries.
 - [x] Multiple authentication methods:
   - with user and password.
   - as current shell user

## Limitations

LDAP paged queries returns **pageSize** results per page, and it takes approximately 1 second to query a page. Therefore your monitoring refresh rate is **(number of LDAP objects // pageSize)** seconds. On most domain controllers **pageSize = 5000**.

## Usage

```
$ ./ldapmonitor.py -h
usage: ldapmonitor.py [-h] [--use-ldaps] [--debug] [--no-colors] [-l LOGFILE] [-r] [-t TIME_DELAY] [--dc-ip ip address] [-d DOMAIN] [-u USER]
                      [--no-pass | -p PASSWORD | -H [LMHASH:]NTHASH | --aes-key hex key] [-k]

Monitor LDAP changes live!

optional arguments:
  -h, --help            show this help message and exit
  --use-ldaps           Use LDAPS instead of LDAP
  --debug               Debug mode.
  --no-colors           No colors mode.
  -l LOGFILE, --logfile LOGFILE
                        Log file to save output to.
  -r, --randomize-delay
                        Randomize delay between two queries, between 1 and 5 seconds.
  -t TIME_DELAY, --time-delay TIME_DELAY
                        Delay between two queries in seconds (default: 1).

authentication & connection:
  --dc-ip ip address    IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN)
                        specified in the identity parameter
  -d DOMAIN, --domain DOMAIN
                        (FQDN) domain to authenticate to
  -u USER, --user USER  user to authenticate with

  --no-pass             don't ask for password (useful for -k)
  -p PASSWORD, --password PASSWORD
                        password to authenticate with
  -H [LMHASH:]NTHASH, --hashes [LMHASH:]NTHASH
                        NT/LM hashes, format is LMhash:NThash
  --aes-key hex key     AES key to use for Kerberos Authentication (128 or 256 bits)
  -k, --kerberos        Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials
                        cannot be found, it will use the ones specified in the command line
```

## Quick start

 - Authenticate with a password:

    ```
    ./ldapmonitor.py -u 'Administrator' -d 'LAB.local' -p 'Admin123!' --dc-ip 192.168.2.1
    ```

 - Authenticate with LM:NT hashes:

    ```
    ./ldapmonitor.py -u 'Administrator' -d 'LAB.local' --dc-ip 192.168.2.1 -H aad3b435b51404eeaad3b435b51404ee:520126a03f5d5a8d836f1c4f34ede7ce
    ```

## Demonstration

https://user-images.githubusercontent.com/79218792/136900209-d2156d4c-d83d-4227-b51e-999ec99b2314.mp4

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.
