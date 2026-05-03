# 程序需要增加下面的功能：

## 增加一种类似反向代理的功能。server 和client 之间建立一条管理通道(admin queue). 通过这个admin queue。 gost client 向gost server 发送 创建连接的命令。命令包含cient 的端口和使用那种协议。

## 支持新增一种代理协议(socksSimple). 
- 把原始数据通过和指定的key 进行 xor 操作进行加密。 发送端把原始数据和key 通过xor 加密发送到server， server 通过可key xor 解密获取原始数据。
- type : 1, 代表admin 管理通道，paloay 需要通过key 进行xor 加密。
- type： 2, 是socksSimple 协议。 payload 是在标准的，通过key 进行xor 加密了。
- 代理协议命令分为两种。一种三创建连接。一种三发送数据请求。

## 协议头部格式可以参考, 你可以根据实际情况修改/添加/, 目的三需要把协议都进行加密传输。（socks5 对于数据部分没有加密）：
struct {
    magic  uint32 // fixed 0x3193
    type   uint8 // 1: admin queue  2: data queue  3: forward channel
    cmd    uint8 // 1: create data queue when type was 1.   2: crete connection to remote when type was 2 or 3.  3: send request when type was 2 or 3 
    len    uint16
    payload []
}

## host A gost (server): 代理流量实际网络出口 
- gost -T=admin://user:key@192.168.10.1:1024
- gost 根据-T admin参数 和IP 192.168.10.1 的 端口1024 建立一条tcp连接，这条连接是用来和192.168.10.1 作管理通道(admin queue)。
- gost 如果从admin queue 收到创建连接命令，palyload 包含data queue的 ip 和端口，解析命令中的ip 和端口， 和p:port  建立多条tcp连接(data queue)。
- gost 把从data queue/forward channel  收到的数据, 先解密(和key 进行xor), 然后根据cmd 判断是创建连接或发送数据请求. response data 同样使用这在加密方式通过data queue/forward channel返回


## hostB gost(client) 192.168.10.1:
- gost -L=socks5://:80 -L=socksSimple://user:key@:90 -R=admin://user:key@:1024 -R=socksSimple://user:key@:1023
- gost 根据-L 参赛在建立一个linten 端口 80, 接受socks5 协议 ,和socksSimple协议
- gost  根据 -R=admin 建立一个listen端口 1024, 把和这个端口建立的连接，当作admin queue。
- gost 根据-R=socksSimple 建立一个listen 端口 1023,  server 会和这个端口建立多条连接(data queue)。 
- gost 把从 80 端口收到的sock5协议，使用当前已有的解析流程，然后转化为-R设定的 协议通过data queue 发送到server。
- gost 把从 90 端口收到的socksSimple协议， 根据socksSimplel协议实现，然后转化为-R设定的 socksSimple协议通过data queue 发送到server。

# host C(user): 
## gost -L=socks5://:6090 -L=http://:6091 -F=socksSimple://user@key:192.168.10.1:80 -D
- gost 把收到的socks5 协议或者http协议，通过当前project 已有的流程 处理。然后转化为socksSimple 协议发给192.168.10.1:80
- 这样就实现了 从user -> client -> server 完整的请求流程
- 可以和目前的其他协议实现方式相同，每个请求使用一个单独的connection。

# 注意点
- 需要考虑视频类型的流量转发
- 需要考虑降低时延，data queue 需要创建连接池

# 你可以尽情发挥，只要实现我的要求。细节你可以自己更改设计方案。

---

# 实现说明 (本次实现细节)

## URL 语法
gost 走标准 URL 解析，所以 `user@key` 写作 `user:key`，例如：
- `-T=admin://u:k@192.168.10.1:1024`
- `-R=admin://u:k@:1024`
- `-R=socksSimple://u:k@:1023`
- `-L=socksSimple://u:k@:90`
- `-F=socksSimple://u:k@192.168.10.1:80`



## 测试
- `admin_test.go` 端到端: A+B+target 三进程在同一进程中 spin up, 通过真实 TCP 跑 HTTP GET
- 手工冒烟: B 跑 `-R=admin -R=socksSimple -L=socksSimple`, A 跑 `-T=admin`, C 跑 -L=socks5 -F=socksSimple `curl --socks5` 通


