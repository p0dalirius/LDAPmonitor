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

```

## Quick start

 - Authenticate with a password:

    ```
    ldapmonitor.exe /dcip:192.168.2.1 /user:user1 /pass:October2021!
    ```

## Demonstration

https://user-images.githubusercontent.com/79218792/136900209-d2156d4c-d83d-4227-b51e-999ec99b2314.mp4

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.
