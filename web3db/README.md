# Web3DB
#### Project Dependencies ####
* Install the latest version of Golang.
* Spin up your own Thread DB instance.
    * Follow their README for build procedure.
        * I reccommend building from their Docker File
* `mv config.example.yaml config.yaml`
    * Fill in `threaddb_addr` and `port` keys
        * `port` is the port listening for HTTP API calls.
        * `threaddb_addr` needs "`ip:port`", (ex.) "127.0.0.1:6006"
            * This information can be found in Thread DB output log shortly after starting up.
    * Leave `rsa_private_key` blank, it will be auto-filled on first run.
* `go run src/main.go`

#### Endpoint Specification ####
- TODO

#### Note ####
* Currently in development.
