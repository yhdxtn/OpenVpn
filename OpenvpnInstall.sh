
#!/bin/bash
# shellcheck disable=SC1091,SC2164,SC2034,SC1072,SC1073,SC1009

# 为 Debian, Ubuntu, CentOS, Amazon Linux 2, Fedora, Oracle Linux 8, Arch Linux, Rocky Linux 和 AlmaLinux 安装安全的 OpenVPN 服务器。
# https://github.com/yhdxtn/OpenVpn

function isRoot() {
	if [ "$EUID" -ne 0 ]; then
		return 1
	fi
}

function tunAvailable() {
	if [ ! -e /dev/net/tun ]; then
		return 1
	fi
}

function checkOS() {
	if [[ -e /etc/debian_version ]]; then
		OS="debian"
		source /etc/os-release

		if [[ $ID == "debian" || $ID == "raspbian" ]]; then
			if [[ $VERSION_ID -lt 9 ]]; then
				echo "⚠️ 您的 Debian 版本不受支持。"
				echo ""
				echo "不过，如果您使用的是 Debian >= 9 或不稳定/测试版本，可以自行决定继续操作。"
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "继续？[y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		elif [[ $ID == "ubuntu" ]]; then
			OS="ubuntu"
			MAJOR_UBUNTU_VERSION=$(echo "$VERSION_ID" | cut -d '.' -f1)
			if [[ $MAJOR_UBUNTU_VERSION -lt 16 ]]; then
				echo "⚠️ 您的 Ubuntu 版本不受支持。"
				echo ""
				echo "不过，如果您使用的是 Ubuntu >= 16.04 或测试版，可以自行决定继续操作。"
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "继续？[y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		fi
	elif [[ -e /etc/system-release ]]; then
		source /etc/os-release
		if [[ $ID == "fedora" || $ID_LIKE == "fedora" ]]; then
			OS="fedora"
		fi
		if [[ $ID == "centos" || $ID == "rocky" || $ID == "almalinux" ]]; then
			OS="centos"
			if [[ ${VERSION_ID%.*} -lt 7 ]]; then
				echo "⚠️ 您的 CentOS 版本不受支持。"
				echo ""
				echo "此脚本仅支持 CentOS 7 和 CentOS 8。"
				echo ""
				exit 1
			fi
		fi
		if [[ $ID == "ol" ]]; then
			OS="oracle"
			if [[ ! $VERSION_ID =~ (8) ]]; then
				echo "您的 Oracle Linux 版本不受支持。"
				echo ""
				echo "此脚本仅支持 Oracle Linux 8。"
				exit 1
			fi
		fi
		if [[ $ID == "amzn" ]]; then
			OS="amzn"
			if [[ $VERSION_ID != "2" ]]; then
				echo "⚠️ 您的 Amazon Linux 版本不受支持。"
				echo ""
				echo "此脚本仅支持 Amazon Linux 2。"
				echo ""
				exit 1
			fi
		fi
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "看起来您不是在 Debian、Ubuntu、Fedora、CentOS、Amazon Linux 2、Oracle Linux 8 或 Arch Linux 系统上运行此安装程序。"
		exit 1
	fi
}

function initialCheck() {
	if ! isRoot; then
		echo "抱歉，您需要以 root 身份运行此脚本"
		exit 1
	fi
	if ! tunAvailable; then
		echo "TUN 不可用"
		exit 1
	fi
	checkOS
}

function installUnbound() {
	# 如果未安装 Unbound，则安装它
	if [[ ! -e /etc/unbound/unbound.conf ]]; then

		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get install -y unbound

			# 配置
			echo 'interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes' >>/etc/unbound/unbound.conf

		elif [[ $OS =~ (centos|amzn|oracle) ]]; then
			yum install -y unbound

			# 配置
			sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
			sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
			sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
			sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
			sed -i 's|use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf

		elif [[ $OS == "fedora" ]]; then
			dnf install -y unbound

			# 配置
			sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
			sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
			sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
			sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
			sed -i 's|# use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf

		elif [[ $OS == "arch" ]]; then
			pacman -Syu --noconfirm unbound

			# 获取根服务器列表
			curl -o /etc/unbound/root.hints https://www.internic.net/domain/named.cache

			if [[ ! -f /etc/unbound/unbound.conf.old ]]; then
				mv /etc/unbound/unbound.conf /etc/unbound/unbound.conf.old
			fi

			echo 'server:
	use-syslog: yes
	do-daemonize: no
	username: "unbound"
	directory: "/etc/unbound"
	trust-anchor-file: trusted-key.key
	root-hints: root.hints
	interface: 10.8.0.1
	access-control: 10.8.0.1/24 allow
	port: 53
	num-threads: 2
	use-caps-for-id: yes
	harden-glue: yes
	hide-identity: yes
	hide-version: yes
	qname-minimisation: yes
	prefetch: yes' >/etc/unbound/unbound.conf
		fi

		# 所有操作系统的 IPv6 DNS
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'interface: fd42:42:42:42::1
access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/unbound.conf
		fi

		if [[ ! $OS =~ (fedora|centos|amzn|oracle) ]]; then
			# DNS 反弹修复
			echo "private-address: 10.0.0.0/8
private-address: fd42:42:42:42::/112
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96" >>/etc/unbound/unbound.conf
		fi
	else # Unbound 已安装
		echo 'include: /etc/unbound/openvpn.conf' >>/etc/unbound/unbound.conf

		# 为 OpenVPN 子网添加 Unbound 'server'
		echo 'server:
interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes
private-address: 10.0.

0.0/8
private-address: fd42:42:42:42::/112
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96' >/etc/unbound/openvpn.conf
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'interface: fd42:42:42:42::1
access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/openvpn.conf
		fi
	fi

	systemctl enable unbound
	systemctl restart unbound
}

function installQuestions() {
	echo "欢迎使用 OpenVPN 安装程序！"
	echo "Git 仓库地址：https://github.com/angristan/openvpn-install"
	echo ""

	echo "在开始设置之前，我需要问你几个问题。"
	echo "你可以保留默认选项，并在确认时按回车键。"
	echo ""
	echo "我需要知道你希望 OpenVPN 监听的网络接口的 IPv4 地址。"
	echo "除非你的服务器在 NAT 后面，否则应该是你的公共 IPv4 地址。"

	# 检测公共 IPv4 地址并预填充
	IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)

	if [[ -z $IP ]]; then
		# 检测公共 IPv6 地址
		IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	APPROVE_IP=${APPROVE_IP:-n}
	if [[ $APPROVE_IP =~ n ]]; then
		read -rp "IP 地址: " -e -i "$IP" IP
	fi
	# 如果 $IP 是私有 IP 地址，服务器必须在 NAT 后面
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo ""
		echo "看起来这台服务器在 NAT 后面。它的公共 IPv4 地址或主机名是什么？"
		echo "我们需要它让客户端连接到服务器。"

		PUBLICIP=$(curl -s https://api.ipify.org)
		until [[ $ENDPOINT != "" ]]; do
			read -rp "公共 IPv4 地址或主机名: " -e -i "$PUBLICIP" ENDPOINT
		done
	fi

	echo ""
	echo "检查 IPv6 连接..."
	echo ""
	# "ping6" 和 "ping -6" 可用性因发行版而异
	if type ping6 >/dev/null 2>&1; then
		PING6="ping6 -c3 ipv6.google.com > /dev/null 2>&1"
	else
		PING6="ping -6 -c3 ipv6.google.com > /dev/null 2>&1"
	fi
	if eval "$PING6"; then
		echo "你的主机似乎有 IPv6 连接。"
		SUGGESTION="y"
	else
		echo "你的主机似乎没有 IPv6 连接。"
		SUGGESTION="n"
	fi
	echo ""
	# 无论是否可用，询问用户是否要启用 IPv6 支持。
	until [[ $IPV6_SUPPORT =~ (y|n) ]]; do
		read -rp "你想启用 IPv6 支持（NAT）吗？[y/n]: " -e -i $SUGGESTION IPV6_SUPPORT
	done
	echo ""
	echo "你希望 OpenVPN 监听哪个端口？"
	echo "   1) 默认：1194"
	echo "   2) 自定义"
	echo "   3) 随机 [49152-65535]"
	until [[ $PORT_CHOICE =~ ^[1-3]$ ]]; do
		read -rp "端口选择 [1-3]: " -e -i 1 PORT_CHOICE
	done
	case $PORT_CHOICE in
	1)
		PORT="1194"
		;;
	2)
		until [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
			read -rp "自定义端口 [1-65535]: " -e -i 1194 PORT
		done
		;;
	3)
		# 生成私有端口范围内的随机数
		PORT=$(shuf -i49152-65535 -n1)
		echo "随机端口: $PORT"
		;;
	esac
	echo ""
	echo "你希望 OpenVPN 使用哪种协议？"
	echo "UDP 更快。除非不可用，否则不应使用 TCP。"
	echo "   1) UDP"
	echo "   2) TCP"
	until [[ $PROTOCOL_CHOICE =~ ^[1-2]$ ]]; do
		read -rp "协议 [1-2]: " -e -i 1 PROTOCOL_CHOICE
	done
	case $PROTOCOL_CHOICE in
	1)
		PROTOCOL="udp"
		;;
	2)
		PROTOCOL="tcp"
		;;
	esac
	echo ""
	echo "你希望 VPN 使用哪些 DNS 解析器？"
	echo "   1) 当前系统解析器（来自 /etc/resolv.conf）"
	echo "   2) 自托管 DNS 解析器（Unbound）"
	echo "   3) Cloudflare (Anycast: 全球)"
	echo "   4) Quad9 (Anycast: 全球)"
	echo "   5) Quad9 未过滤版 (Anycast: 全球)"
	echo "   6) FDN (法国)"
	echo "   7) DNS.WATCH (德国)"
	echo "   8) OpenDNS (Anycast: 全球)"
	echo "   9) Google (Anycast: 全球)"
	echo "   10) Yandex Basic (俄罗斯)"
	echo "   11) AdGuard DNS (Anycast: 全球)"
	echo "   12) NextDNS (Anycast: 全球)"
	echo "   13) 自定义"
	until [[ $DNS =~ ^[0-9]+$ ]] && [ "$DNS" -ge 1 ] && [ "$DNS" -le 13 ]; do
		read -rp "DNS [1-12]: " -e -i 11 DNS
		if [[ $DNS == 2 ]] && [[ -e /etc/unbound/unbound.conf ]]; then
			echo ""
			echo "Unbound 已安装。"
			echo "你可以允许脚本配置它，以便从 OpenVPN 客户端使用它。"
			echo "我们将简单地为 OpenVPN 子网添加第二个服务器到 /etc/unbound/unbound.conf。"
			echo "不会对当前配置进行任何更改。"
			echo ""

			until [[ $CONTINUE =~ (y|n) ]]; do
				read -rp "应用配置更改到 Unbound？[y/n]: " -e CONTINUE
			done
			if [[ $CONTINUE == "n" ]]; then
				# 中断循环并清理
				unset DNS
				unset CONTINUE
			fi
		elif [[ $DNS == "13" ]]; then
			until [[ $DNS1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
				read -rp "主 DNS: " -e DNS1
			done
			until [[ $DNS2 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
				read -rp "次要 DNS（可选）: " -e DNS2
				if [[ $DNS2 == "" ]]; then
					break
				fi
			done
		fi
	done
	echo ""
	echo "你想启用压缩吗？由于 VORACLE 攻击，建议不启用。"
	until [[ $COMPRESSION_ENABLED =~ (y|n) ]]; do
		read -rp"启用压缩？[y/n]: " -e -i n COMPRESSION_ENABLED
	done
	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "选择你要使用的压缩算法：（按效率排序）"
		echo "   1) LZ4-v2"
		echo "   2) LZ4"
		echo "   3) LZ0"
		until [[ $COMPRESSION_CHOICE =~ ^[1-3]$ ]]; do
			read -rp"压缩算法 [1-3]: " -e

 -i 1 COMPRESSION_CHOICE
		done
		case $COMPRESSION_CHOICE in
		1)
			COMPRESSION_ALG="lz4-v2"
			;;
		2)
			COMPRESSION_ALG="lz4"
			;;
		3)
			COMPRESSION_ALG="lzo"
			;;
		esac
	fi
	echo ""
	echo "你想自定义加密设置吗？"
	echo "除非你知道自己在做什么，否则你应该坚持使用脚本提供的默认参数。"
	echo "请注意，无论你选择什么，脚本中提供的所有选择都是安全的。（不像 OpenVPN 的默认设置）"
	echo "查看更多信息请访问：https://github.com/angristan/openvpn-install#security-and-encryption"
	echo ""
	until [[ $CUSTOMIZE_ENC =~ (y|n) ]]; do
		read -rp "自定义加密设置？[y/n]: " -e -i n CUSTOMIZE_ENC
	done
	if [[ $CUSTOMIZE_ENC == "n" ]]; then
		# 使用默认、安全且快速的参数
		CIPHER="AES-128-GCM"
		CERT_TYPE="1" # ECDSA
		CERT_CURVE="prime256v1"
		CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
		DH_TYPE="1" # ECDH
		DH_CURVE="prime256v1"
		HMAC_ALG="SHA256"
		TLS_SIG="1" # tls-crypt
	else
		echo ""
		echo "选择你想用于数据通道的加密算法："
		echo "   1) AES-128-GCM（推荐）"
		echo "   2) AES-192-GCM"
		echo "   3) AES-256-GCM"
		echo "   4) AES-128-CBC"
		echo "   5) AES-192-CBC"
		echo "   6) AES-256-CBC"
		until [[ $CIPHER_CHOICE =~ ^[1-6]$ ]]; do
			read -rp "加密算法 [1-6]: " -e -i 1 CIPHER_CHOICE
		done
		case $CIPHER_CHOICE in
		1)
			CIPHER="AES-128-GCM"
			;;
		2)
			CIPHER="AES-192-GCM"
			;;
		3)
			CIPHER="AES-256-GCM"
			;;
		4)
			CIPHER="AES-128-CBC"
			;;
		5)
			CIPHER="AES-192-CBC"
			;;
		6)
			CIPHER="AES-256-CBC"
			;;
		esac
		echo ""
		echo "选择你想用于证书的密钥类型："
		echo "   1) ECDSA（推荐）"
		echo "   2) RSA"
		until [[ $CERT_TYPE =~ ^[1-2]$ ]]; do
			read -rp"证书密钥类型 [1-2]: " -e -i 1 CERT_TYPE
		done
		case $CERT_TYPE in
		1)
			echo ""
			echo "选择你想用于证书密钥的曲线："
			echo "   1) prime256v1（推荐）"
			echo "   2) secp384r1"
			echo "   3) secp521r1"
			until [[ $CERT_CURVE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp"曲线 [1-3]: " -e -i 1 CERT_CURVE_CHOICE
			done
			case $CERT_CURVE_CHOICE in
			1)
				CERT_CURVE="prime256v1"
				;;
			2)
				CERT_CURVE="secp384r1"
				;;
			3)
				CERT_CURVE="secp521r1"
				;;
			esac
			;;
		2)
			echo ""
			echo "选择你想用于证书密钥的 RSA 密钥大小："
			echo "   1) 2048 位（推荐）"
			echo "   2) 3072 位"
			echo "   3) 4096 位"
			until [[ $RSA_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "RSA 密钥大小 [1-3]: " -e -i 1 RSA_KEY_SIZE_CHOICE
			done
			case $RSA_KEY_SIZE_CHOICE in
			1)
				RSA_KEY_SIZE="2048"
				;;
			2)
				RSA_KEY_SIZE="3072"
				;;
			3)
				RSA_KEY_SIZE="4096"
				;;
			esac
			;;
		esac
		echo ""
		echo "选择你想用于控制通道的加密算法："
		case $CERT_TYPE in
		1)
			echo "   1) ECDHE-ECDSA-AES-128-GCM-SHA256（推荐）"
			echo "   2) ECDHE-ECDSA-AES-256-GCM-SHA384"
			until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
				read -rp"控制通道加密算法 [1-2]: " -e -i 1 CC_CIPHER_CHOICE
			done
			case $CC_CIPHER_CHOICE in
			1)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
				;;
			2)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
				;;
			esac
			;;
		2)
			echo "   1) ECDHE-RSA-AES-128-GCM-SHA256（推荐）"
			echo "   2) ECDHE-RSA-AES-256-GCM-SHA384"
			until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
				read -rp"控制通道加密算法 [1-2]: " -e -i 1 CC_CIPHER_CHOICE
			done
			case $CC_CIPHER_CHOICE in
			1)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"
				;;
			2)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"
				;;
			esac
			;;
		esac
		echo ""
		echo "选择你想用于 Diffie-Hellman 密钥的类型："
		echo "   1) ECDH（推荐）"
		echo "   2) DH"
		until [[ $DH_TYPE =~ [1-2] ]]; do
			read -rp"DH 密钥类型 [1-2]: " -e -i 1 DH_TYPE
		done
		case $DH_TYPE in
		1)
			echo ""
			echo "选择你想用于 ECDH 密钥的曲线："
			echo "   1) prime256v1（推荐）"
			echo "   2) secp384r1"
			echo "   3) secp521r1"
			while [[ $DH_CURVE_CHOICE != "1" && $DH_CURVE_CHOICE != "2" && $DH_CURVE_CHOICE != "3" ]]; do
				read -rp"曲线 [1-3]: " -e -i 1 DH_CURVE_CHOICE
			done
			case $DH_CURVE_CHOICE in
			1)
				DH_CURVE="prime256v1"
				;;
			2)
				DH_CURVE="secp384r1"
				;;
			3)
				DH_CURVE="secp521r1"
				;;
			esac
			;;
		2)
			echo ""
			echo "选择你想用于 Diffie-Hellman 密钥的大小："
			echo "   1) 2048 位（推荐）"
			echo "   2) 3072 位"
			echo "   3) 4096 位"
			until [[ $DH_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "DH 密钥大小 [1-3]: " -e -i 1 DH_KEY_SIZE_CHOICE
			done
			case $DH_KEY_SIZE_CHOICE in
			1)
				DH_KEY_SIZE="2048"
				;;
			2)
				DH_KEY_SIZE="3072"
				;;
			3)
				DH_KEY_SIZE="4096"
				;;
			esac
			;;
		esac
		echo ""
		# "auth" 选项在 AEAD 加密算法中表现不同
		if [[ $CIPHER =~ CBC$ ]]; then
			echo "摘要算法用于验证数据通道数据包和控制通道中的 tls-auth 数据包。"
		elif [[ $CIPHER =~ GCM$ ]]; then
			echo "摘要算法用于验证控制通道中的 tls-auth 数据包。"
		fi

	echo "你希望使用哪种摘要算法进行 HMAC？"
	echo "   1) SHA-256（推荐）"
	echo "   2) SHA-384"
	echo "   3) SHA-512"
	until [[ $HMAC_ALG_CHOICE =~ ^[1-3]$ ]]; do
		read -rp "摘要算法 [1-3]: " -e -i 1 HMAC_ALG_CHOICE
	done
	case $HMAC_ALG_CHOICE in
	1)
		HMAC_ALG="SHA256"
		;;
	2)
		HMAC_ALG="SHA384"
		;;
	3)
		HMAC_ALG="SHA512"
		;;
	esac
	echo ""
	echo "你可以为控制通道添加额外的安全层，使用 tls-auth 和 tls-crypt"
	echo "tls-auth 认证数据包，而 tls-crypt 认证并加密数据包。"
	echo "   1) tls-crypt（推荐）"
	echo "   2) tls-auth"
	until [[ $TLS_SIG =~ [1-2] ]]; do
		read -rp "控制通道额外的安全机制 [1-2]: " -e -i 1 TLS_SIG
	done
fi
echo ""
echo "好了，这就是我需要的所有信息。我们现在准备设置你的 OpenVPN 服务器了。"
echo "安装完成后你可以生成客户端配置文件。"
APPROVE_INSTALL=${APPROVE_INSTALL:-n}
if [[ $APPROVE_INSTALL =~ n ]]; then
	read -n1 -r -p "按任意键继续..."
fi
}

function installOpenVPN() {
if [[ $AUTO_INSTALL == "y" ]]; then
	# 设置默认选项，这样就不会再询问问题。
	APPROVE_INSTALL=${APPROVE_INSTALL:-y}
	APPROVE_IP=${APPROVE_IP:-y}
	IPV6_SUPPORT=${IPV6_SUPPORT:-n}
	PORT_CHOICE=${PORT_CHOICE:-1}
	PROTOCOL_CHOICE=${PROTOCOL_CHOICE:-1}
	DNS=${DNS:-1}
	COMPRESSION_ENABLED=${COMPRESSION_ENABLED:-n}
	CUSTOMIZE_ENC=${CUSTOMIZE_ENC:-n}
	CLIENT=${CLIENT:-client}
	PASS=${PASS:-1}
	CONTINUE=${CONTINUE:-y}

	# 在 NAT 后，我们将默认使用可公开访问的 IPv4/IPv6 地址。
	if [[ $IPV6_SUPPORT == "y" ]]; then
		if ! PUBLIC_IP=$(curl -f --retry 5 --retry-connrefused https://ip.seeip.org); then
			PUBLIC_IP=$(dig -6 TXT +short o-o.myaddr.l.google.com @ns1.google.com | tr -d '"')
		fi
	else
		if ! PUBLIC_IP=$(curl -f --retry 5 --retry-connrefused -4 https://ip.seeip.org); then
			PUBLIC_IP=$(dig -4 TXT +short o-o.myaddr.l.google.com @ns1.google.com | tr -d '"')
		fi
	fi
	ENDPOINT=${ENDPOINT:-$PUBLIC_IP}
fi

# 首先运行设置问题，如果是自动安装则设置其他变量
installQuestions

# 从默认路由获取“公共”接口
NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
if [[ -z $NIC ]] && [[ $IPV6_SUPPORT == 'y' ]]; then
	NIC=$(ip -6 route show default | sed -ne 's/^default .* dev \([^ ]*\) .*$/\1/p')
fi

# $NIC 不能为脚本 rm-openvpn-rules.sh 为空
if [[ -z $NIC ]]; then
	echo
	echo "无法检测到公共接口。"
	echo "这需要设置 MASQUERADE。"
	until [[ $CONTINUE =~ (y|n) ]]; do
		read -rp "继续？[y/n]: " -e CONTINUE
	done
	if [[ $CONTINUE == "n" ]]; then
		exit 1
	fi
fi

# 如果 OpenVPN 尚未安装，则安装它。此脚本在多次运行时大致幂等，但仅在第一次时从上游安装 OpenVPN。
if [[ ! -e /etc/openvpn/server.conf ]]; then
	if [[ $OS =~ (debian|ubuntu) ]]; then
		apt-get update
		apt-get -y install ca-certificates gnupg
		# 我们添加 OpenVPN 仓库以获取最新版本。
		if [[ $VERSION_ID == "16.04" ]]; then
			echo "deb http://build.openvpn.net/debian/openvpn/stable xenial main" >/etc/apt/sources.list.d/openvpn.list
			wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
			apt-get update
		fi
		# Ubuntu > 16.04 和 Debian > 8 无需第三方仓库即可拥有 OpenVPN >= 2.4。
		apt-get install -y openvpn iptables openssl wget ca-certificates curl
	elif [[ $OS == 'centos' ]]; then
		yum install -y epel-release
		yum install -y openvpn iptables openssl wget ca-certificates curl tar 'policycoreutils-python*'
	elif [[ $OS == 'oracle' ]]; then
		yum install -y oracle-epel-release-el8
		yum-config-manager --enable ol8_developer_EPEL
		yum install -y openvpn iptables openssl wget ca-certificates curl tar policycoreutils-python-utils
	elif [[ $OS == 'amzn' ]]; then
		amazon-linux-extras install -y epel
		yum install -y openvpn iptables openssl wget ca-certificates curl
	elif [[ $OS == 'fedora' ]]; then
		dnf install -y openvpn iptables openssl wget ca-certificates curl policycoreutils-python-utils
	elif [[ $OS == 'arch' ]]; then
		# 安装所需依赖项并升级系统
		pacman --needed --noconfirm -Syu openvpn iptables openssl wget ca-certificates curl
	fi
	# 在某些 openvpn 包中默认可用的旧版 easy-rsa
	if [[ -d /etc/openvpn/easy-rsa/ ]]; then
		rm -rf /etc/openvpn/easy-rsa/
	fi
fi

# 查找机器是否使用 nogroup 或 nobody 作为无权限组
if grep -qs "^nogroup:" /etc/group; then
	NOGROUP=nogroup
else
	NOGROUP=nobody
fi

# 如果尚未安装，则从源代码安装最新版本的 easy-rsa。
if [[ ! -d /etc/openvpn/easy-rsa/ ]]; then
	local version="3.1.2"
	wget -O ~/easy-rsa.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v${version}/EasyRSA-${version}.tgz
	mkdir -p /etc/openvpn/easy-rsa
	tar xzf ~/easy-rsa.tgz --strip-components=1 --no-same-owner --directory /etc/openvpn/easy-rsa
	rm -f ~/easy-rsa.tgz

	cd /etc/openvpn/easy-rsa/ || return
	case $CERT_TYPE in
	1)
		echo "set_var EASYRSA_ALGO ec" >vars
		echo "set_var EASYRSA_CURVE $CERT_CURVE" >>vars
		;;
	2)
		echo "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" >vars
		;;
	esac

	# 生成一个 16 个字符的随机字母数字标识符，用于 CN 和服务器名称
	SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
	echo "$SERVER_CN" >SERVER_CN_GENERATED
	SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
	echo "$SERVER_NAME" >SERVER_NAME_GENERATED

	# 创建 PKI，设置 CA、DH 参数和服务器证书
	./easyrsa init-pki
	./easyrsa --batch --req-cn="$SERVER_CN" build-ca nopass

	if [[ $DH_TYPE == "2" ]]; then
		# ECDH 密钥是即时生成的，因此我们不需要预先生成它们
		openssl dhparam -out dh.pem $DH_KEY_SIZE
	fi

	./easyrsa --batch build-server-full "$SERVER_NAME" nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

	case $TLS_SIG in
	1)
		# 生成 tls-crypt 密钥
		openvpn --genkey --secret /etc/openvpn/tls-crypt.key
		;;
	2)
		# 生成 tls-auth 密钥
		openvpn --genkey --secret /etc/openvpn/tls-auth.key
		;;
	esac
else
	# 如果已经安装了 easy-rsa，则获取生成的 SERVER_NAME 用于客户端配置
	cd /etc/openvpn/easy-rsa/ || return
	SERVER_NAME=$(cat SERVER_NAME_GENERATED

)
fi

# 移动所有生成的文件
cp pki/ca.crt pki/private/ca.key "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
if [[ $DH_TYPE == "2" ]]; then
	cp dh.pem /etc/openvpn
fi

# 使证书吊销列表对非 root 用户可读
chmod 644 /etc/openvpn/crl.pem

# 生成 server.conf
echo "port $PORT" >/etc/openvpn/server.conf
if [[ $IPV6_SUPPORT == 'n' ]]; then
	echo "proto $PROTOCOL" >>/etc/openvpn/server.conf
elif [[ $IPV6_SUPPORT == 'y' ]]; then
	echo "proto ${PROTOCOL}6" >>/etc/openvpn/server.conf
fi

echo "dev tun
user nobody
group $NOGROUP
persist-key
persist-tun
keepalive 10 120
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" >>/etc/openvpn/server.conf

# DNS 解析器
case $DNS in
1) # 当前系统解析器
	# 定位正确的 resolv.conf
	# 对于运行 systemd-resolved 的系统是必须的
	if grep -q "127.0.0.53" "/etc/resolv.conf"; then
		RESOLVCONF='/run/systemd/resolve/resolv.conf'
	else
		RESOLVCONF='/etc/resolv.conf'
	fi
	# 从 resolv.conf 获取解析器并将它们用于 OpenVPN
	sed -ne 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*$/\1/p' $RESOLVCONF | while read -r line; do
		# 复制，如果是 IPv4 |或| 如果启用 IPv6，则 IPv4/IPv6 无关
		if [[ $line =~ ^[0-9.]*$ ]] || [[ $IPV6_SUPPORT == 'y' ]]; then
			echo "push \"dhcp-option DNS $line\"" >>/etc/openvpn/server.conf
		fi
	done
	;;
2) # 自托管 DNS 解析器（Unbound）
	echo 'push "dhcp-option DNS 10.8.0.1"' >>/etc/openvpn/server.conf
	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo 'push "dhcp-option DNS fd42:42:42:42::1"' >>/etc/openvpn/server.conf
	fi
	;;
3) # Cloudflare
	echo 'push "dhcp-option DNS 1.0.0.1"' >>/etc/openvpn/server.conf
	echo 'push "dhcp-option DNS 1.1.1.1"' >>/etc/openvpn/server.conf
	;;
4) # Quad9
	echo 'push "dhcp-option DNS 9.9.9.9"' >>/etc/openvpn/server.conf
	echo 'push "dhcp-option DNS 149.112.112.112"' >>/etc/openvpn/server.conf
	;;
5) # Quad9 未过滤版
	echo 'push "dhcp-option DNS 9.9.9.10"' >>/etc/openvpn/server.conf
	echo 'push "dhcp-option DNS 149.112.112.10"' >>/etc/openvpn/server.conf
	;;
6) # FDN
	echo 'push "dhcp-option DNS 80.67.169.40"' >>/etc/openvpn/server.conf
	echo 'push "dhcp-option DNS 80.67.169.12"' >>/etc/openvpn/server.conf
	;;
7) # DNS.WATCH
	echo 'push "dhcp-option DNS 84.200.69.80"' >>/etc/openvpn/server.conf
	echo 'push "dhcp-option DNS 84.200.70.40"' >>/etc/openvpn/server.conf
	;;
8) # OpenDNS
	echo 'push "dhcp-option DNS 208.67.222.222"' >>/etc/openvpn/server.conf
	echo 'push "dhcp-option DNS 208.67.220.220"' >>/etc/openvpn/server.conf
	;;
9) # Google
	echo 'push "dhcp-option DNS 8.8.8.8"' >>/etc/openvpn/server.conf
	echo 'push "dhcp-option DNS 8.8.4.4"' >>/etc/openvpn/server.conf
	;;
10) # Yandex Basic
	echo 'push "dhcp-option DNS 77.88.8.8"' >>/etc/openvpn/server.conf
	echo 'push "dhcp-option DNS 77.88.8.1"' >>/etc/openvpn/server.conf
	;;
11) # AdGuard DNS
	echo 'push "dhcp-option DNS 94.140.14.14"' >>/etc/openvpn/server.conf
	echo 'push "dhcp-option DNS 94.140.15.15"' >>/etc/openvpn/server.conf
	;;
12) # NextDNS
	echo 'push "dhcp-option DNS 45.90.28.167"' >>/etc/openvpn/server.conf
	echo 'push "dhcp-option DNS 45.90.30.167"' >>/etc/openvpn/server.conf
	;;
13) # 自定义 DNS
	echo "push \"dhcp-option DNS $DNS1\"" >>/etc/openvpn/server.conf
	if [[ $DNS2 != "" ]]; then
		echo "push \"dhcp-option DNS $DNS2\"" >>/etc/openvpn/server.conf
	fi
	;;
esac
echo 'push "redirect-gateway def1 bypass-dhcp"' >>/etc/openvpn/server.conf

# 如果需要，IPv6 网络设置
if [[ $IPV6_SUPPORT == 'y' ]]; then
	echo 'server-ipv6 fd42:42:42:42::/112
tun-ipv6
push tun-ipv6
push "route-ipv6 2000::/3"
push "redirect-gateway ipv6"' >>/etc/openvpn/server.conf
fi

if [[ $COMPRESSION_ENABLED == "y" ]]; then
	echo "compress $COMPRESSION_ALG" >>/etc/openvpn/server.conf
fi

if [[ $DH_TYPE == "1" ]]; then
	echo "dh none" >>/etc/openvpn/server.conf
	echo "ecdh-curve $DH_CURVE" >>/etc/openvpn/server.conf
elif [[ $DH_TYPE == "2" ]]; then
	echo "dh dh.pem" >>/etc/openvpn/server.conf
fi

case $TLS_SIG in
1)
	echo "tls-crypt tls-crypt.key" >>/etc/openvpn/server.conf
	;;
2)
	echo "tls-auth tls-auth.key 0" >>/etc/openvpn/server.conf
	;;
esac

echo "crl-verify crl.pem
ca ca.crt
cert $SERVER_NAME.crt
key $SERVER_NAME.key
auth $HMAC_ALG
cipher $CIPHER
ncp-ciphers $CIPHER
tls-server
tls-version-min 1.2
tls-cipher $CC_CIPHER
client-config-dir /etc/openvpn/ccd
status /var/log/openvpn/status.log
verb 3" >>/etc/openvpn/server.conf

# 创建 client-config-dir 目录
mkdir -p /etc/openvpn/ccd
# 创建日志目录
mkdir -p /var/log/openvpn

# 启用路由
echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
if [[ $IPV6_SUPPORT == 'y' ]]; then
	echo 'net.ipv6.conf.all.forwarding=1' >>/etc/sysctl.d/99-openvpn.conf
fi
# 应用 sysctl 规则
sysctl --system

# 如果启用了 SELinux 并选择了自定义端口，我们需要这个
if hash sestatus 2>/dev/null; then
	if sestatus | grep "Current mode" | grep -qs "enforcing"; then
		if [[ $PORT != '1194' ]]; then
			semanage port -a -t openvpn_port_t -p "$PROTOCOL" "$PORT"
		fi
	fi
fi

# 最后，重启并启用 OpenVPN
if [[ $OS == 'arch' || $OS == 'fedora' || $OS == 'centos' || $OS == 'oracle' ]]; then
	# 不修改包提供的服务
	cp /usr/lib/systemd/system/openvpn-server@.service /etc/systemd/system/openvpn-server@.service

	# 修复 OpenVPN 服务在 OpenVZ 上的问题
	sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn-server@.service
	# 另一个继续使用 /etc/openvpn/ 的解决方法
	sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn-server@.service

	systemctl daemon-reload
	systemctl enable openvpn-server@server
	systemctl restart openvpn-server@server
elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
	# 在 Ubuntu 16.04 上，我们使用来自 OpenVPN 仓库的包
	# 这个包使用一个 sysvinit 服务
	systemctl enable open

vpn
	systemctl start openvpn
else
	# 不修改包提供的服务
	cp /lib/systemd/system/openvpn\@.service /etc/systemd/system/openvpn\@.service

	# 修复 OpenVPN 服务在 OpenVZ 上的问题
	sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn\@.service
	# 另一个继续使用 /etc/openvpn/ 的解决方法
	sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn\@.service

	systemctl daemon-reload
	systemctl enable openvpn@server
	systemctl restart openvpn@server
fi

if [[ $DNS == 2 ]]; then
	installUnbound
fi

# 在两个脚本中添加 iptables 规则
mkdir -p /etc/iptables

# 添加规则的脚本
echo "#!/bin/sh
iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -I INPUT 1 -i tun0 -j ACCEPT
iptables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
iptables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
iptables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/add-openvpn-rules.sh

if [[ $IPV6_SUPPORT == 'y' ]]; then
	echo "ip6tables -t nat -I POSTROUTING 1 -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -I INPUT 1 -i tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
ip6tables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/add-openvpn-rules.sh
fi

# 删除规则的脚本
echo "#!/bin/sh
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -D INPUT -i tun0 -j ACCEPT
iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT
iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT
iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/rm-openvpn-rules.sh

if [[ $IPV6_SUPPORT == 'y' ]]; then
	echo "ip6tables -t nat -D POSTROUTING -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -D INPUT -i tun0 -j ACCEPT
ip6tables -D FORWARD -i $NIC -o tun0 -j ACCEPT
ip6tables -D FORWARD -i tun0 -o $NIC -j ACCEPT
ip6tables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/rm-openvpn-rules.sh
fi

chmod +x /etc/iptables/add-openvpn-rules.sh
chmod +x /etc/iptables/rm-openvpn-rules.sh

# 通过 systemd 脚本处理规则
echo "[Unit]
Description=iptables rules for OpenVPN
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" >/etc/systemd/system/iptables-openvpn.service

# 启用服务并应用规则
systemctl daemon-reload
systemctl enable iptables-openvpn
systemctl start iptables-openvpn

# 如果服务器在 NAT 后，请使用正确的 IP 地址让客户端连接到服务器
if [[ $ENDPOINT != "" ]]; then
	IP=$ENDPOINT
fi

# client-template.txt 被创建，以便以后可以添加更多用户
echo "client" >/etc/openvpn/client-template.txt
if [[ $PROTOCOL == 'udp' ]]; then
	echo "proto udp" >>/etc/openvpn/client-template.txt
	echo "explicit-exit-notify" >>/etc/openvpn/client-template.txt
elif [[ $PROTOCOL == 'tcp' ]]; then
	echo "proto tcp-client" >>/etc/openvpn/client-template.txt
fi
echo "remote $IP $PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name $SERVER_NAME name
auth $HMAC_ALG
auth-nocache
cipher $CIPHER
tls-client
tls-version-min 1.2
tls-cipher $CC_CIPHER
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns # 防止 Windows 10 DNS 泄漏
verb 3" >>/etc/openvpn/client-template.txt

if [[ $COMPRESSION_ENABLED == "y" ]]; then
	echo "compress $COMPRESSION_ALG" >>/etc/openvpn/client-template.txt
fi

# 生成自定义的 client.ovpn
newClient
echo "如果你想添加更多客户端，只需再次运行此脚本！"
}

function newClient() {
echo ""
echo "告诉我客户端的名称。"
echo "名称必须由字母数字字符组成。它还可以包含下划线或破折号。"

until [[ $CLIENT =~ ^[a-zA-Z0-9_-]+$ ]]; do
	read -rp "客户端名称: " -e CLIENT
done

echo ""
echo "你想用密码保护配置文件吗？"
echo "（例如，用密码加密私钥）"
echo "   1) 添加无密码客户端"
echo "   2) 使用密码保护客户端"

until [[ $PASS =~ ^[1-2]$ ]]; do
	read -rp "选择一个选项 [1-2]: " -e -i 1 PASS
done

CLIENTEXISTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c -E "/CN=$CLIENT\$")
if [[ $CLIENTEXISTS == '1' ]]; then
	echo ""
	echo "指定的客户端 CN 已在 easy-rsa 中找到，请选择其他名称。"
	exit
else
	cd /etc/openvpn/easy-rsa/ || return
	case $PASS in
	1)
		./easyrsa --batch build-client-full "$CLIENT" nopass
		;;
	2)
		echo "⚠️ 你将在下面被要求输入客户端密码 ⚠️"
		./easyrsa --batch build-client-full "$CLIENT"
		;;
	esac
	echo "客户端 $CLIENT 已添加。"
fi

# 用户的主目录，将写入客户端配置文件
if [ -e "/home/${CLIENT}" ]; then
	# 如果 $1 是用户名
	homeDir="/home/${CLIENT}"
elif [ "${SUDO_USER}" ]; then
	# 如果不是，使用 SUDO_USER
	if [ "${SUDO_USER}" == "root" ]; then
		# 如果以 root 身份运行 sudo
		homeDir="/root"
	else
		homeDir="/home/${SUDO_USER}"
	fi
else
	# 如果不是 SUDO_USER，使用 /root
	homeDir="/root"
fi

# 确定我们使用的是 tls-auth 还是 tls-crypt
if grep -qs "^tls-crypt" /etc/openvpn/server.conf; then
	TLS_SIG="1"
elif grep -qs "^tls-auth" /etc/openvpn/server.conf; then
	TLS_SIG="2"
fi

# 生成自定义的 client.ovpn
cp /etc/openvpn/client-template.txt "$homeDir/$CLIENT.ovpn"
{
	echo "<ca>"
	cat "/etc/openvpn/easy-rsa/pki/ca.crt"
	echo "</ca>"

	echo "<cert>"
	awk '/BEGIN/,/END CERTIFICATE/' "/etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt"
	echo "</cert>"

	echo "<key>"
	cat "/etc/openvpn/easy-rsa/pki/private/$CLIENT.key"
	echo "</key>"

	case $TLS_SIG in
	1)
		echo "<tls-crypt>"
		cat /etc/openvpn/tls-crypt.key
		echo "</tls-crypt>"
		;;
	2)
		echo "key-direction 1"
		echo "<tls-auth>"
		cat /etc/openvpn/tls-auth.key
		echo "</tls-auth>"
		;;
	esac
} >>"$homeDir/$CLIENT.ovpn"

echo ""
echo "配置文件已写入 $homeDir/$CLIENT.ovpn。"
echo "下载 .ovpn 文件并将其导入你的 OpenVPN 客户端。"

exit 0
}

function revokeClient() {
NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
if [[ $NUMBEROFCLIENTS == '0' ]]; then
	echo ""
	echo "你

没有现有的客户端！"
	exit 1
fi

echo ""
echo "选择你想吊销的现有客户端证书"
tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
until [[ $CLIENTNUMBER -ge 1 && $CLIENTNUMBER -le $NUMBEROFCLIENTS ]]; do
	if [[ $CLIENTNUMBER == '1' ]]; then
		read -rp "选择一个客户端 [1]: " CLIENTNUMBER
	else
		read -rp "选择一个客户端 [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
	fi
done
CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
cd /etc/openvpn/easy-rsa/ || return
./easyrsa --batch revoke "$CLIENT"
EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
rm -f /etc/openvpn/crl.pem
cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
chmod 644 /etc/openvpn/crl.pem
find /home/ -maxdepth 2 -name "$CLIENT.ovpn" -delete
rm -f "/root/$CLIENT.ovpn"
sed -i "/^$CLIENT,.*/d" /etc/openvpn/ipp.txt
cp /etc/openvpn/easy-rsa/pki/index.txt{,.bk}

echo ""
echo "客户端 $CLIENT 的证书已吊销。"
}

function removeUnbound() {
# 移除与 OpenVPN 相关的配置
sed -i '/include: \/etc\/unbound\/openvpn.conf/d' /etc/unbound/unbound.conf
rm /etc/unbound/openvpn.conf

until [[ $REMOVE_UNBOUND =~ (y|n) ]]; do
	echo ""
	echo "如果你在安装 OpenVPN 之前已经使用 Unbound，我移除了与 OpenVPN 相关的配置。"
	read -rp "你想完全移除 Unbound 吗？[y/n]: " -e REMOVE_UNBOUND
done

if [[ $REMOVE_UNBOUND == 'y' ]]; then
	# 停止 Unbound
	systemctl stop unbound

	if [[ $OS =~ (debian|ubuntu) ]]; then
		apt-get remove --purge -y unbound
	elif [[ $OS == 'arch' ]]; then
		pacman --noconfirm -R unbound
	elif [[ $OS =~ (centos|amzn|oracle) ]]; then
		yum remove -y unbound
	elif [[ $OS == 'fedora' ]]; then
		dnf remove -y unbound
	fi

	rm -rf /etc/unbound/

	echo ""
	echo "Unbound 已移除！"
else
	systemctl restart unbound
	echo ""
	echo "Unbound 未被移除。"
fi
}

function removeOpenVPN() {
echo ""
read -rp "你真的想移除 OpenVPN 吗？[y/n]: " -e -i n REMOVE
if [[ $REMOVE == 'y' ]]; then
	# 从配置中获取 OpenVPN 端口
	PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
	PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)

	# 停止 OpenVPN
	if [[ $OS =~ (fedora|arch|centos|oracle) ]]; then
		systemctl disable openvpn-server@server
		systemctl stop openvpn-server@server
		# 移除定制服务
		rm /etc/systemd/system/openvpn-server@.service
	elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
		systemctl disable openvpn
		systemctl stop openvpn
	else
		systemctl disable openvpn@server
		systemctl stop openvpn@server
		# 移除定制服务
		rm /etc/systemd/system/openvpn\@.service
	fi

	# 移除与脚本相关的 iptables 规则
	systemctl stop iptables-openvpn
	# 清理
	systemctl disable iptables-openvpn
	rm /etc/systemd/system/iptables-openvpn.service
	systemctl daemon-reload
	rm /etc/iptables/add-openvpn-rules.sh
	rm /etc/iptables/rm-openvpn-rules.sh

	# SELinux
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ $PORT != '1194' ]]; then
				semanage port -d -t openvpn_port_t -p "$PROTOCOL" "$PORT"
			fi
		fi
	fi

	if [[ $OS =~ (debian|ubuntu) ]]; then
		apt-get remove --purge -y openvpn
		if [[ -e /etc/apt/sources.list.d/openvpn.list ]]; then
			rm /etc/apt/sources.list.d/openvpn.list
			apt-get update
		fi
	elif [[ $OS == 'arch' ]]; then
		pacman --noconfirm -R openvpn
	elif [[ $OS =~ (centos|amzn|oracle) ]]; then
		yum remove -y openvpn
	elif [[ $OS == 'fedora' ]]; then
		dnf remove -y openvpn
	fi

	# 清理
	find /home/ -maxdepth 2 -name "*.ovpn" -delete
	find /root/ -maxdepth 1 -name "*.ovpn" -delete
	rm -rf /etc/openvpn
	rm -rf /usr/share/doc/openvpn*
	rm -f /etc/sysctl.d/99-openvpn.conf
	rm -rf /var/log/openvpn

	# Unbound
	if [[ -e /etc/unbound/openvpn.conf ]]; then
		removeUnbound
	fi
	echo ""
	echo "OpenVPN 已移除！"
else
	echo ""
	echo "移除已中止！"
fi
}

function manageMenu() {
echo "欢迎使用 OpenVPN-install！"
echo "Git 仓库地址：https://github.com/angristan/openvpn-install"
echo ""
echo "看起来 OpenVPN 已经安装。"
echo ""
echo "你想做什么？"
echo "   1) 添加新用户"
echo "   2) 吊销现有用户"
echo "   3) 移除 OpenVPN"
echo "   4) 退出"
until [[ $MENU_OPTION =~ ^[1-4]$ ]]; do
	read -rp "选择一个选项 [1-4]: " MENU_OPTION
done

case $MENU_OPTION in
1)
	newClient
	;;
2)
	revokeClient
	;;
3)
	removeOpenVPN
	;;
4)
	exit 0
	;;
esac
}

# 检查 root、TUN、OS...
initialCheck

# 检查 OpenVPN 是否已经安装
if [[ -e /etc/openvpn/server.conf && $AUTO_INSTALL != "y" ]]; then
manageMenu
else
installOpenVPN
fi
