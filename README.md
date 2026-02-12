Simple Ray (Keep it simple, stupid)

fork from: [https://github.com/XTLS/Xray-core](https://github.com/XTLS/Xray-core)

#### removed features
* vmess, ss, hy2, tun, wireguard
* kcp, reality, ech
* reverse, grpc api, cmd api
* yaml/toml config formats

If you need any feature above, download [XTLS/Xray-core](https://github.com/XTLS/Xray-core) instead.

#### compile
```bash
go build -v -o "simple-ray" -trimpath -ldflags "-s -w -buildid=" ./main
```

