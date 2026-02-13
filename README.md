Simple Ray (Keep it simple, stupid)

Fork from: [https://github.com/XTLS/Xray-core](https://github.com/XTLS/Xray-core)

#### Removed features
* vmess, ss, hy2, tun, wireguard
* kcp, reality, ech
* reverse, grpc api, cmd api
* yaml/toml config formats

If you need any feature above, download [XTLS/Xray-core](https://github.com/XTLS/Xray-core) instead.

#### Compile
```bash
go build -v -o "simple-ray" -trimpath -ldflags "-s -w -buildid=" ./main
```

