# openvpn-install

![测试](https://github.com/angristan/openvpn-install/workflows/Test/badge.svg)
![代码检查](https://github.com/angristan/openvpn-install/workflows/Lint/badge.svg)
[![说声谢谢！](https://img.shields.io/badge/Say%20Thanks-!-1EAEDB.svg)](https://saythanks.io/to/angristan)

适用于 Debian、Ubuntu、Fedora、CentOS、Arch Linux、Oracle Linux、Rocky Linux 和 AlmaLinux 的 OpenVPN 安装脚本。

此脚本将让你在几秒钟内设置自己的安全 VPN 服务器。

你也可以看看 [wireguard-install](https://github.com/angristan/wireguard-install)，它是一个简单的安装程序，用于更简单、更安全、更快速和更现代的 VPN 协议。

## 使用方法

首先，获取脚本并使其可执行：

```bash
curl -O https://github.com/yhdxtn/master/openvpn-install.sh
chmod +x openvpn-install.sh
```

然后运行它：

```sh
./openvpn-install.sh
```

你需要以 root 用户身份运行该脚本，并启用 TUN 模块。

第一次运行时，你需要按照助手的指引并回答几个问题来设置你的 VPN 服务器。

安装 OpenVPN 后，你可以再次运行该脚本，你将有以下选择：

- 添加客户端
- 删除客户端
- 卸载 OpenVPN

在你的主目录中，你将拥有 `.ovpn` 文件。这些是客户端配置文件。将它们从服务器下载并使用你喜欢的 OpenVPN 客户端连接。

如果你有任何问题，请先查看 [FAQ](#faq)。请在打开问题之前阅读所有内容。

**请不要给我发送电子邮件或私人消息请求帮助。** 唯一可以获得帮助的地方是问题区。其他人可能会提供帮助，将来也可能会遇到与你相同的问题。我的时间不是免费提供给你的，你并不特别。

### 无人值守安装

也可以在无人值守的情况下运行脚本，例如在自动化的方式下，无需等待用户输入。

示例用法：

```bash
AUTO_INSTALL=y ./openvpn-install.sh

# 或者

export AUTO_INSTALL=y
./openvpn-install.sh
```

然后将设置默认的一组变量，跳过用户输入的需求。

如果你想自定义安装，可以像上面那样导出或在同一行中指定它们。

- `APPROVE_INSTALL=y`
- `APPROVE_IP=y`
- `IPV6_SUPPORT=n`
- `PORT_CHOICE=1`
- `PROTOCOL_CHOICE=1`
- `DNS=1`
- `COMPRESSION_ENABLED=n`
- `CUSTOMIZE_ENC=n`
- `CLIENT=clientname`
- `PASS=1`

如果服务器位于 NAT 之后，你可以使用 `ENDPOINT` 变量指定其端点。如果端点是它背后的公共 IP 地址，你可以使用 `ENDPOINT=$(curl -4 ifconfig.co)`（脚本默认使用此地址）。端点可以是 IPv4 或域名。

根据你的选择（加密、压缩），可以设置其他变量。你可以在脚本的 `installQuestions()` 函数中搜索它们。

由于 Easy-RSA 需要用户输入，无人值守安装方法不支持密码保护的客户端。

无人值守安装在某种程度上是幂等的，因为它已经安全地多次运行具有相同参数，例如由 Ansible/Terraform/Salt/Chef/Puppet 等状态配置器运行。只有在 Easy-RSA PKI 不存在时才会安装和重新生成，并且仅在未安装 OpenVPN 时才会安装 OpenVPN 和其他上游依赖项。每次无人值守运行时，它都会重新创建所有本地配置并重新生成客户端文件。

### 无人值守添加用户

也可以自动化添加新用户。这里的关键是在调用脚本之前提供 `MENU_OPTION` 变量的（字符串）值以及其他必要变量。

以下 Bash 脚本将新用户 `foo` 添加到现有的 OpenVPN 配置中

```bash
#!/bin/bash
export MENU_OPTION="1"
export CLIENT="foo"
export PASS="1"
./openvpn-install.sh
```

## 功能

- 安装并配置即用型 OpenVPN 服务器
- 以无缝方式管理 iptables 规则和转发
- 如有需要，脚本可以清理移除 OpenVPN，包括配置和 iptables 规则
- 可定制的加密设置，增强的默认设置（见下文 [Security and Encryption](#security-and-encryption)）
- OpenVPN 2.4 功能，主要是加密改进（见下文 [Security and Encryption](#security-and-encryption)）
- 推送给客户端的各种 DNS 解析器
- 选择使用自托管解析器（支持已存在的 Unbound 安装）
- 在 TCP 和 UDP 之间选择
- 支持 NATed IPv6
- 默认禁用压缩以防止 VORACLE。提供 LZ4（v1/v2）和 LZO 算法
- 非特权模式：以 `nobody`/`nogroup` 运行
- 阻止 Windows 10 上的 DNS 泄漏
- 随机化服务器证书名称
- 选择使用密码保护客户端（私钥加密）
- 许多其他小功能！

## 兼容性

该脚本支持这些 Linux 发行版：

|                    | 支持情况  |
| ------------------ | ------- |
| AlmaLinux 8        | ✅      |
| Amazon Linux 2     | ✅      |
| Arch Linux         | ✅      |
| CentOS 7           | ✅ 🤖   |
| CentOS Stream >= 8 | ✅ 🤖   |
| Debian >= 10       | ✅ 🤖   |
| Fedora >= 35       | ✅ 🤖   |
| Oracle Linux 8     | ✅      |
| Rocky Linux 8      | ✅      |
| Ubuntu >= 18.04    | ✅ 🤖   |

需要注意：

- 该脚本定期针对标有 🤖 的发行版进行测试。
  - 仅在 `amd64` 架构上进行测试。
- 应该可以在较旧版本（如 Debian 8+、Ubuntu 16.04+ 和之前的 Fedora 版本）上运行。但上表中未列出的版本不在官方支持范围内。
  - 也应该支持 LTS 版本之间的版本，但这些版本未经过测试。
- 该脚本需要 `systemd`。

## 分支

该脚本基于 [Nyr 和其贡献者](https://github.com/Nyr/openvpn-install) 的出色工作。

自 2016 年以来，这两个脚本已发生分歧，尤其是在底层方面。该脚本的主要目标是增强安全性。但从那时起，该脚本已被完全重写，并增加了许多功能。不过该脚本仅兼容最新的发行版，因此如果你需要使用非常旧的服务器或客户端，建议使用 Nyr 的脚本。

## 常见问题解答

更多问答请见 [FAQ.md](FAQ.md)。

**问:** 你推荐哪个服务提供商？

**答:** 我推荐以下这些：

- [Vultr](https://www.vultr.com/?ref=8948982-8H)：全球各地，支持 IPv6，起价 5 美元/月
- [Hetzner](https://hetzner.cloud/?ref=ywtlvZsjgeDq)：德国、芬兰和美国。支持 IPv6，每月 4.5 欧元起，20 TB 流量
- [Digital Ocean](https://m.do.co/c/ed0ba143fe53)：全球各地，支持 IPv6，起价 4 美元/月

---

**问:** 你推荐哪个 OpenVPN 客户端？

**答:** 如果可能，推荐使用官方 OpenVPN 2.4 客户端。

- Windows：[官方 OpenVPN 社区客户端](https://openvpn.net/index.php/download/community-downloads.html)。
- Linux：你发行版中的 `openvpn` 包。Debian/Ubuntu 系发行版有一个 [官方 APT 仓库](https://community.openvpn.net/openvpn/wiki/OpenvpnSoftwareRepos)。
- macOS：[Tunnelblick](https://tunnelblick.net/)、[Viscosity](https://www.sparklabs.com/viscosity/)、[OpenVPN for Mac](https://openvpn.net/client-connect-vpn-for-mac-os/)。
- Android：[OpenVPN for Android](https://play.google.com/store/apps/details?id=de.blinkt.openvpn)。
- iOS：[官方 OpenVPN Connect 客户端](https://itunes.apple.com/us/app/openvpn-connect/id590379981)。

---

**问:** 使用你的脚本我能避开 NSA 的监视吗？

**答:** 请审查你的威胁模型。即使这个脚本考虑到了安全性并使用了最先进的加密技术，如果你想躲避 NSA 的监视，你不应该使用 VPN。

---

**问:** 是否有 OpenVPN 文档？

**答:** 是的，请访问 [OpenVPN 手册](https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage)，其中参考了所有选项。

---

更多问答请见 [FAQ.md

](FAQ.md)。

## 一站式公有云解决方案

基于此脚本提供即用型 OpenVPN 服务器的解决方案可用于：

- 使用 Terraform 在 AWS 上的 [`openvpn-terraform-install`](https://github.com/dumrauf/openvpn-terraform-install)
- Terraform AWS 模块 [`openvpn-ephemeral`](https://registry.terraform.io/modules/paulmarsicloud/openvpn-ephemeral/aws/latest)

## 贡献

## 讨论变更

如果你想讨论变更，尤其是大的变更，请在提交 PR 之前打开一个问题。

### 代码格式化

我们使用 [shellcheck](https://github.com/koalaman/shellcheck) 和 [shfmt](https://github.com/mvdan/sh) 来执行 bash 样式指南和良好实践。它们通过 GitHub Actions 对每个提交/PR 进行执行，因此你可以在 [这里](https://github.com/angristan/openvpn-install/blob/master/.github/workflows/push.yml) 检查配置。

## 安全性和加密

> **警告**
> 这还没有针对 OpenVPN 2.5 及以后版本更新。

OpenVPN 的默认设置在加密方面相当弱。此脚本旨在改进这一点。

OpenVPN 2.4 是在加密方面的重大更新。它增加了对 ECDSA、ECDH、AES GCM、NCP 和 tls-crypt 的支持。

如果你想了解下文提到的选项的更多信息，请访问 [OpenVPN 手册](https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage)。它非常完整。

大多数与 OpenVPN 加密相关的内容由 [Easy-RSA](https://github.com/OpenVPN/easy-rsa) 管理。默认参数在 [vars.example](https://github.com/OpenVPN/easy-rsa/blob/v3.0.7/easyrsa3/vars.example) 文件中。

### 压缩

默认情况下，OpenVPN 不启用压缩。此脚本提供对 LZO 和 LZ4（v1/v2）算法的支持，后者更高效。

然而，不建议使用压缩，因为 [VORACLE 攻击](https://protonvpn.com/blog/voracle-attack/) 利用它。

### TLS 版本

OpenVPN 默认接受 TLS 1.0，这个版本几乎有 [20 年的历史](https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_1.0)。

通过 `tls-version-min 1.2` 我们强制使用 TLS 1.2，这是当前 OpenVPN 可用的最佳协议。

TLS 1.2 自 OpenVPN 2.3.3 起支持。

### 证书

OpenVPN 默认使用 2048 位密钥的 RSA 证书。

OpenVPN 2.4 增加了对 ECDSA 的支持。椭圆曲线密码学更快、更轻、更安全。

此脚本提供：

- ECDSA：`prime256v1`/`secp384r1`/`secp521r1` 曲线
- RSA：`2048`/`3072`/`4096` 位密钥

默认为 `prime256v1` 的 ECDSA。

OpenVPN 默认使用 `SHA-256` 作为签名哈希，脚本也是如此。目前不提供其他选择。

### 数据通道

默认情况下，OpenVPN 使用 `BF-CBC` 作为数据通道密码。Blowfish 是一种古老（1993 年）且弱的算法。即使是官方 OpenVPN 文档也承认这一点。

> 默认是 BF-CBC，代表块密码链接模式下的 Blowfish。
>
> 不再推荐使用 BF-CBC，因为它的块大小为 64 位。由于块大小较小，可以进行基于碰撞的攻击，如 SWEET32 所示。详情请参阅 <https://community.openvpn.net/openvpn/wiki/SWEET32>。
> INRIA 的安全研究人员发表了一项关于 64 位块密码（如 3DES 和 Blowfish）的攻击。他们展示了如何在经常发送相同数据时恢复明文，并展示了如何利用跨站脚本漏洞经常发送感兴趣的数据。这适用于 HTTPS，也适用于 HTTP-over-OpenVPN。详情请参阅 <https://sweet32.info/>。
>
> OpenVPN 的默认密码 BF-CBC 受此攻击影响。

确实，AES 是当今的标准。它是当前可用的最快和最安全的密码。[SEED](https://en.wikipedia.org/wiki/SEED) 和 [Camellia](<https://en.wikipedia.org/wiki/Camellia_(cipher)>) 目前没有被攻破，但比 AES 慢，相对来说不太受信任。

> 在当前支持的密码中，OpenVPN 目前推荐使用 AES-256-CBC 或 AES-128-CBC。OpenVPN 2.4 及更高版本还将支持 GCM。对于 2.4+，我们推荐使用 AES-256-GCM 或 AES-128-GCM。

AES-256 比 AES-128 慢 40%，没有任何实际理由使用 256 位密钥而不是 128 位密钥（来源：[1](http://security.stackexchange.com/questions/14068/why-most-people-use-256-bit-encryption-instead-of-128-bit)、[2](http://security.stackexchange.com/questions/6141/amount-of-simple-operations-that-is-safely-out-of-reach-for-all-humanity/6149#6149)）。此外，AES-256 更容易受到 [定时攻击](https://en.wikipedia.org/wiki/Timing_attack)。

AES-GCM 是一种 [AEAD 密码](https://en.wikipedia.org/wiki/Authenticated_encryption)，这意味着它同时提供数据的机密性、完整性和真实性。

该脚本支持以下密码：

- `AES-128-GCM`
- `AES-192-GCM`
- `AES-256-GCM`
- `AES-128-CBC`
- `AES-192-CBC`
- `AES-256-CBC`

默认使用 `AES-128-GCM`。

OpenVPN 2.4 增加了一项名为“NCP”的功能：_Negotiable Crypto Parameters_。这意味着你可以像 HTTPS 一样提供密码套件。默认设置为 `AES-256-GCM:AES-128-GCM`，并在与 OpenVPN 2.4 客户端一起使用时覆盖 `--cipher` 参数。为了简化起见，脚本将 `--cipher` 和 `--ncp-cipher` 设置为上述选择的密码。

### 控制通道

OpenVPN 2.4 默认将协商最佳可用密码（例如 ECDHE+AES-256-GCM）

脚本根据证书提供以下选项：

- ECDSA：
  - `TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256`
  - `TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384`
- RSA：
  - `TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256`
  - `TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384`

默认为 `TLS-ECDHE-*-WITH-AES-128-GCM-SHA256`。

### Diffie-Hellman 密钥交换

OpenVPN 默认使用 2048 位 DH 密钥。

OpenVPN 2.4 增加了对 ECDH 密钥的支持。椭圆曲线密码学更快、更轻、更安全。

此外，生成经典的 DH 密钥可能需要很长时间。ECDH 密钥是临时的：它们是即时生成的。

脚本提供以下选项：

- ECDH：`prime256v1`/`secp384r1`/`secp521r1` 曲线
- DH：`2048`/`3072`/`4096` 位密钥

默认为 `prime256v1`。

### HMAC 摘要算法

关于 `--auth`，来自 OpenVPN 维基：

> 使用 HMAC 通过消息摘要算法 alg 认证数据通道包和（如果启用）tls-auth 控制通道包。（默认是 SHA1）。HMAC 是一种常用的消息认证算法（MAC），它使用数据字符串、安全哈希算法和密钥来生成数字签名。
>
> 如果选择 AEAD 密码模式（例如 GCM），则指定的 --auth 算法将被忽略用于数据通道，而使用 AEAD 密码的认证方法。请注意，alg 仍然指定用于 tls-auth 的摘要。

脚本提供以下选择：

- `SHA256`
- `SHA384`
- `SHA512`

默认使用 `SHA256`。

### `tls-auth` 和 `tls-crypt`

关于 `tls-auth`，来自 OpenVPN 维基：

> 在 TLS 控制通道之上添加额外的 HMAC 认证层，以减轻 DoS 攻击和对 TLS 栈的攻击。
>
> 简而言之，--tls-auth 在 OpenVPN 的 TCP/UDP 端口上启用了一种“HMAC 防火墙”，其中 TLS 控制通道包带有错误的 HMAC 签名可以立即被丢弃而不响应。

关于 `tls-crypt`：

> 使用 keyfile 中的密钥加密和

认证所有控制通道包。（有关更多背景，请参阅 --tls-auth。）
>
> 加密（和认证）控制通道包：
>
> - 通过隐藏用于 TLS 连接的证书提供更多隐私，
> - 使识别 OpenVPN 流量更加困难，
> - 提供“穷人的”后量子安全性，针对永远不知道预共享密钥的攻击者（即无前向保密性）。

因此，两者都提供了额外的安全层，并减轻了 DoS 攻击。默认情况下，OpenVPN 不使用它们。

`tls-crypt` 是 OpenVPN 2.4 的功能，除了认证外还提供加密（不像 `tls-auth`）。它更隐私友好。

脚本支持两者，默认使用 `tls-crypt`。

## 说声谢谢

如果你愿意，可以 [说声谢谢](https://saythanks.io/to/angristan)！

## 版权及许可证

非常感谢 [贡献者](https://github.com/Angristan/OpenVPN-install/graphs/contributors) 和 Nyr 的原创工作。

此项目采用 [MIT 许可证](https://raw.githubusercontent.com/Angristan/openvpn-install/master/LICENSE)。
