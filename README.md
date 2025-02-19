## 使用的时候需要将网卡绑定的通道数设置和参数queueNum一致，使用如下命令设置
```shell
sudo ethtool -L enp6s0 combined 1
```