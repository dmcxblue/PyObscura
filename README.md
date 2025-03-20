# PyObscura
## About
With some great tools like Sourcepoint I wanted to try and replicate the usage of it, but since I am not quite capable to write this in GO I am using O'l reliable python.


## Usage

```python
    ____        ____  __
   / __ \__  __/ __ \/ /_  ____________  ___________ _
  / /_/ / / / / / / / __ \/ ___/ ___/ / / / ___/ __ `/
 / ____/ /_/ / /_/ / /_/ (__  ) /__/ /_/ / /  / /_/ /
/_/    \__, /\____/_.___/____/\___/\__,_/_/   \__,_/
      /____/
****************************************************
*                                                  *
*        Cobalt Strike C2 profile Generator        *
*                      v1.0                        *
*                 Author: dmcxblue                 *
*                                                  *
****************************************************

usage: PyObscura.py [-h] --outprofile OUTPROFILE --sleep SLEEP --jitter JITTER [--datajitter DATAJITTER] [--useragent USERAGENT] [--spawnto SPAWNTO] [--injection INJECTION] [--library LIBRARY]
                    [--syscall SYSCALL] [--beacongate BEACONGATE] [--forwarder FORWARDER] --url URL --geturi GETURI --posturi POSTURI

Use this tool to build customized C2 profiles.

options:
  -h, --help            show this help message and exit
  --outprofile OUTPROFILE
                        Path to the output profile file.
  --host HOST           Team Server Domain name
  --sleep SLEEP         Sleep time in milliseconds.
  --jitter JITTER       Jitter time.
  --datajitter DATAJITTER
                        Data Jitter time. [Default 50]
  --useragent USERAGENT
                        Beacon User Agent. [Default: Randomized]
  --spawnto SPAWNTO     Spawn to Binary for PostEx.
  --injection INJECTION
                        VirtualAllocEx, NtMapViewOfSection [Default: VirtualAllocEx]
  --library LIBRARY     Select the default HTTP Beacon library (wininet, winhttp) [Default: winhttp]
  --syscall SYSCALL     Defines the ability to use direct/indirect system calls [Default: None] Example: Direct, Indirect, None
  --beacongate BEACONGATE
                        APIs which beacon gate will work on [--beacongate ExitThread *Individually | --beacongate Core *By Groups], [Default: All]
  --forwarder FORWARDER
                        Enabled the X-forwarded-For header (If you are using Relay and are behind a proxy set to True)
  --url URL             URL to query for HTTP response
  --geturi GETURI       Directory from main url for GET, e.g., /about
  --posturi POSTURI     Directory from main url for POST, e.g., /contact

Thank you for using the C2 Profile Builder!
```

The script is almost entirely automated. It prompts the user for information to build a C2 profile from a template by replacing hardcoded placeholders (e.g., %name%). In some sections, it automatically fills in the details—for example, by selecting a User-Agent from a frequently updated list of modern User-Agents (https://jnrbsn.github.io/user-agents/user-agents.json).

Additionally, the script can automate the Request and Response sections of the GET and POST requests in your Malleable profile. By using the --url, --geturi, and --posturi flags, these values are automatically inserted into the profile it will also fill in the the headers and use the prepend and append method for hiding our beacon traffic as seen below.

```txt
################################################
## HTTP GET
################################################
http-get {
    set verb "POST";
    set uri "/c/credit-center";
    client {
        header "X-Device-Type" "desktop";
        header "X-XSS-Protection" "0";
        metadata {
            mask;
            base64url;
            prepend "HD_DC=origin; path=/; domain=.homedepot.com;";
            append " secure, akacd_usbeta=3919930858~rv=93~id=9d31a032cdd207022d3e672128b49174; path=/; Secure; SameSite=None, bm_ss=ab8e18ef4e";
            print;
        }
    }
    server {
        output {
            mask;
            base64url;
            prepend "HD_DC=origin; path=/; domain=.homedepot.com;";
            append " secure, akacd_usbeta=3919930858~rv=93~id=9d31a032cdd207022d3e672128b49174; path=/; Secure; SameSite=None, bm_ss=ab8e18ef4e";
            print;
        }
        header "Expect-CT" "max-age=0";
        header "Accept-Ranges" "bytes";
        header "X-TM-ZONE" "us-central1-f";
        header "Strict-Transport-Security" "max-age=63072000; includeSubDomains";
        header "X-Permitted-Cross-Domain-Policies" "none";
        header "X-Download-Options" "noopen";
    }
}

################################################
## HTTP POST
################################################
http-post {
    set verb "POST";
    set uri "/c/gift-cards`";
    client {
        header "X-Device-Type" "desktop";
        header "X-XSS-Protection" "0";
        id {
            mask;
            base64url;
            prepend "HD_DC=origin;";
            append " path=/";
            print;
        }
        output {
            mask;
            base64url;
            parameter "desktop";
        }
    }
    server {
        output {
            mask;
            base64url;
            prepend "HD_DC=origin;";
            append " path=/";
            print;
        }
        header "X-TM-ZONE" "us-central1-c";
        header "Strict-Transport-Security" "max-age=63072000; includeSubDomains";
        header "X-Permitted-Cross-Domain-Policies" "none";
        header "X-Download-Options" "noopen";
        header "Server" "nginx";
        header "X-Varnish" "294446851 294757142";
        header "X-Varnish-Cache" "HIT(1)@vdir";
        header "grace" "none";
    }
}
```

The following demonstrates a quick usage on the creation of a Malleable C2 Profile, this profile simulates browsing the HomeDepot website

https://github.com/user-attachments/assets/3d616718-b427-47d9-8c3c-79ba24907dde

Always verify if the Malleable profile is fully functional with Cobalt Strike by using the `./c2lint` executable that verifies if the profile is functional.

https://github.com/user-attachments/assets/95c8fe7a-499b-4c96-8e7c-caddc0ce1b6f



