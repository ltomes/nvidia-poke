# Nvidia dive 🤿

## Main target nv_node
On windows, Nvidia packages an undocumented utility called NvNode. This is a web server that runs on all machines with Nvidia video cards and drivers installed. The process runs under the `NVIDIA Web Helper.exe` name. The process is actually a Node `11.13.0.0` binary.

## What communicates with nv_node/service taxonomy?
- Geforce Experience process
- NvTelemetry - Telemetry provider, nothing starts without this.
- NvContainer
- NVBroadcast
- ShadowPlay


## Testing environment:
- Fresh driver install/after DDU
- GFE Version: 3.23.0.74
- Driver Version: 471.96

  But NvNode is not using any of the express template engine features.

  The api expects `x_local_security_cookie` to be in the header, need to investigate if any other services are leaking this...


## Potential attack surfaces: 
  * Prototype Pollution from query string
    - https://snyk.io/test/npm/express/4.14.1
    - Prototype Override Protection Bypass in query string? https://snyk.io/vuln/npm:qs:20170213 
  * Node 11.13.0.0 is Old! Do we have any CVE-2017-5941 like RCEs to exploit?
  * Smuggling:
    - https://github.com/neex/http2smugl
    - https://portswigger.net/daily-swig/http-request-smuggling-http-2-opens-a-new-attack-tunnel
    http2smugl didn't identify a binary exploit in fuzz testing.
  * GFE is not checking ssl certs...so thats fun:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-31597#vulnCurrentDescriptionTitle
    - https://vuldb.com/?id.173811
  * Express is susceptible to this LFR vulnerability:
  - https://blog.shoebpatel.com/2021/01/23/The-Secret-Parameter-LFR-and-Potential-RCE-in-NodeJS-Apps/
  - In my testing, NvNode is not using any of the express template engine features, other services may be (GE?).

## Useful filesystem locations
  1. Source: `%ProgramFiles(x86)%\NVIDIA Corporation\NvNode`
  1. Dev: `%USERPROFILE%\projects\nvidia-dive\playground\NvNode`
  1. Logs: `%USERPROFILE%\AppData\Local\NVIDIA Corporation\NvNode`

  ### Notes
  NWH port rolls on every start of the service.
  get it via: `netstat -ano -p tcp -b | Select-String -Pattern 'NVIDIA Web Helper.exe' -Context 0,3` in an admin powershell session the response should look like this:

```
>  [NVIDIA Web Helper.exe]
    TCP    127.0.0.1:54848        127.0.0.1:54867        ESTABLISHED     27328
>  [NVIDIA Web Helper.exe]
    TCP    127.0.0.1:54867        127.0.0.1:54848        ESTABLISHED     22616
   [NVIDIA Share.exe]
    TCP    127.0.0.1:54910        127.0.0.1:54911        ESTABLISHED     29220
```

  Getting it at attack time: nmap all ports on the host, curl each listening port @ `127.0.0.1:<p>` and check for a response of `Security token is invalid` with a custom Header of `X_LOCAL_SECURITY_COOKIE`