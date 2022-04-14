### MySQL 写 WebShell 有几种方式，利用条件 (★★★)

(1) 多种方式
union select 后写入
lines terminated by 写入
lines starting by 写入
fields terminated by 写入
COLUMNS terminated by 写入
(2) 利用条件

·root 权限
·GPC 关闭（能使用单引号），magic_quotes_gpc=On
·有绝对路径（读文件可以不用，写文件必须）
·没有配置–secure-file-priv
·有读写的权限，有 create、insert、select 的权限

### 攻防实战中你有哪些优秀案例 (★★★★)

(1) 红队：
省级 市级
介绍自己在团队中的负责部分
主要做的是：外网打点，扩大资产，上免杀，横向=》vlan 内网、域控组策略 gpo。（这里简单给几个关键词）

(2) 蓝队：
主要做的是： 1.反打扫描 IP，分析肉鸡，找攻击者的利用工具，配置文件，连接 ip 2.微步查询得到该 IP,找到注册人邮箱,利用邮箱社工 3.各种各样的蜜罐（商用/开源） 4.溯源钓鱼邮件，分析附件木马回连地址，邮件头找到真实发件人，利用邮件信息及 id 去社工，寻找博客，企业信息，社交信息等
获取 id 之后，百度，谷歌，src，微博，微信，支付宝，豆瓣，贴吧，知乎，脉脉，钉钉，CSDN，facebook，领英，github 等进行查询绘制攻击者画像

### XSS 分类和防护,反射型 XSS 和 DOM 型 XSS 的区别 (★★)

(1) 分类
反射型 XSS、DOM 型 XSS、储存型 XSS

(2) 防护

·httpOnly 防止读 cookie（可被绕过）
·实体化编码输出（主要多个输出点/输出平台）
·参数白名单
·增加 Waf 设备，cdn 等

(3)区别
· DOM 型不经过服务器，通过网页本身的 JavaScript 进行渲染触发的
· 反射 XSS 经过服务器

### sql 注入原理，sql 注入类型，防护方式 (★★★

(1) 原理

把用户输入的恶意代码拼接到了数据库查询语句中

(1) 联合查询注入
(2) 报错注入
(3) 布尔盲注
(4) 时间盲注
(5) 堆叠查询
(6) 二次注入
(7) 宽字节注入

防护方式：

1）设备方式：增加 waf,cdn 等

2）代码方式：一般推荐用框架，比如 mybatis 中使用 %获取参数是直接进行拼接 #获取参数是进行预编译

### sql 注入使用预编译之后，是否可以完全修复？ (★★★)

不可以
·如果 sql 语句是 order by，那么预编译是不会生效的
在 Mybatis 的一些场景，使用#会报错
如果一定要使用 order by,推荐的安全方案是，使用 Mybatis 自带的<choose>指令
·一定要记住使用#{}，如果使用${},预编译也不会生效
·能使用白名单，最好就使用白名单

### 渗透测试流程 (★★)

1. 信息收集
   ip、域名、子域名、端口、邮箱、公众号、小程序、生活号、应用、指纹、操作系统、版本、中间件、waf、网盘、github、gitee、语雀、股权架构

2）漏洞探测
端口漏洞
端口弱口令
目录探测
Web 应用漏洞-poc 扫描
管理后台漏洞
逻辑漏洞
等等

3. 绕 waf
   绕 waf 进行漏洞利用( 1 注释替换空格 2 字符集绕过 3 chunked 绕过 4 上传请求 multipart 绕过 5.参数污染 6.垃圾数据污染)

4）拿到 webshell 之后，提权
windows 提权:1.systminfo 根据系统补丁提权 2.第三方服务提权 3.数据库提权
linux 提权:1.利用系统内核漏洞进行提权 2.泄漏密码提权 3.sudo 提权 4.SUID 提权

5}内网横向
CS msf
域控

6）清理痕迹，输出报告

### App 安全测试 (★★★)

(1)安卓：
drozer 审计安卓 app adb 来操作 drozer，四大组件
Activity、Service、Broadcast Receiver、Content Provider

反编译：
如果加固可以尝试用 github 上的 frida-dexdump 脱壳

破解防御：
信任证书，
APK 的安全机制，自签名证书（Xposed - JustTrustMe，SSLUnPinning），用 proxifier 代理工具。Hook 技术（只需要 Hook 证书校验失败的处理方法，让其继续加载页面并保持通讯即可。）
客户端内置代理，hook "system.setproperty" 设置代理到本地
客户端检测是否开启代理（修改 smail 代码绕过，或者 nop 掉检测方法）

双向认证绕过：做了双向验证的 apk,反编译后在 APK 的 assets 中就可以找到客户端证书 .p12 和.cer 的文件，导入时会需要一个证书密码，一般可以通过静态分析代码，搜索 KeyStore 或者 逆向分析客户端的.p12 来找到密码。

接口测试其实跟 Web 渗透一样

### 如何设计开发漏扫平台 (★★)

(1) 确定好开发语言：
一般使用框架来开发代码：

前端:用 Vue 或者 React
后端:用 SpringBoot 或者 Go(gin/goframe/http.server)

(2) 设计好平台逻辑
比如：你作为甲方，你肯定会在自家 waf 给自己的扫描 IP 加个白名单，有必要去是被 Waf,肯定没必要
比如: 你是挖 SRC，你觉得你不需要去识别 Waf,现在稍微正常的公司，他都会有 Waf,有些公司业务比较杂，乱，可能没上 WAf，甚至担心 WAF 影响业务，导致没开，那肯定疯狂扫他（记得有授权）

域名=》子域名（oneforall）=》IP、端口、cdn、waf（放弃自动化扫描/代理池）、C 段=》端口爆破=》端口漏洞=》Web 服务=》Web 目录扫描=》Web 爬虫=》Web 漏洞
masscan 扫全端口，nmap 扫 masscan 扫到存活的端口

(3) 发现漏洞进行告警（邮件/企业微信机器人/钉钉机器人/）

### 应急响应怎么策划,怎么做 (★★)

(1)应急响应 PDCERF 模型
Prepare（准备）
Detection（检测）：

紧急事件监测：包括防火墙、系统、web 服务器、IDS/WAF/SIEM 中的日志，不正常或者是执行了越权操作的用户，甚至还有管理员的报告
Containment（抑制）：

首先先控制受害范围，不要让攻击的影响继续蔓延到其他的 IT 资产和业务环境，切记不要直接一股脑的投入全部精力到封堵后门。紧接着要做的是去寻找根源原因，彻底解决，封堵攻击源，把业务恢复到更张水平
Eradication（根除）
Recover（恢复）
Follow-Up（跟踪）

(2)

内存信息 free -m `htop
系统进程 ps top netstat ss
路由信息 tracert
ifconfig 查看网卡流量，检查网卡的发送、接收数据情况
NetHogs 实时监控带宽占用状况
查看 Linux 系统日志 /var/log
查看系统计划任务

### PHP 熟悉的函数 (★★)

1）代码执行：
eval,preg_replace+/e,assert,call_user_func,call_user_func_array,create_function
2）文件读取：
file_get_contents(),highlight_file(),fopen(),read
file(),fread(),fgetss(), fgets(),parse_ini_file(),show_source(),file()等 3)命令执行：
system(), exec(), shell_exec(), passthru() ,pcntl_exec(), popen(),proc_open()

### Redis 未授权访问漏洞如何入侵利用 (★★)

redis 漏洞产生原因

(1) redis 绑定在 0.0.0.0:6379，且没有添加防火墙规则直接暴露在公网
(2) 没有设置密码认证
(3) root 权限运行

redis 利用方法
·写 crontab 利用计划任务反弹 shell
·开启 ssh 端口，写公钥获得系统权限
·知道 web 目录写 webshell
·redis 4.x 之后,主从复制 getshell

### SSRF 漏洞原理、利用方式及修复方案？Java 和 PHP 的 SSRF 区别？ (★★★)

(1) SSRF 漏洞原理
原理：利用服务当作跳板来攻击其他服务

(2) SSRF 漏洞可能存在
·分享：通过 url 地址分享网页内容
·转码：通过 URL 地址把原地址的网页内容调优使其适合手机屏幕浏览
·在线翻译：通过 URL 地址翻译对应文本的内容
·图片加载与下载：通过 URL 地址加载或下载图片
·图片、文章收藏功能

主要看 api 接口

(3) SSRF 漏洞利用

·利用 file 协议读取文件
·利用 dict 协议查看端口开放
·利用 gopher 协议反弹 shell

(4) SSRF 漏洞利用绕过
·使用@：http://A.com@10.10.10.10 = 10.10.10.10
·IP 地址转换成十进制、八进制：127.0.0.1 = 2130706433
·使用短地址：http://10.10.116.11 = http://t.cn/RwbLKDx
·端口绕过：ip 后面加一个端口

<!-- ·xip.io：10.0.0.1.xip.io = 10.0.0.1 -->

·通过 js 跳转..
·利用 DNS 解析
·利用句号（127。0。0。1）
·利用[::]（http://[::]:80/）；
·利用短地址（http://dwz.cn/11SMa）；
·协议（Dict://、SFTP://、TFTP://、LDAP://、Gopher://）

(5) SSRF 漏洞修复方式：
·使用正则对参数进行效验，防止畸形请求绕过黑名单。
·过滤返回信息，验证远程服务器对请求的响应是比较容易的方法；
·统一错误信息，避免用户可以根据错误信息来判断远端服务器的端口状态；
·限制请求的端口为 http 常用的端口，比如，80,443,8080,8090；
·黑名单内网 ip。避免应用被用来获取获取内网数据，攻击内网；
·禁用不需要的协议。仅允许 http 和 https 请求；
·禁止 30x 跳转

(6) Java 和 PHP 的 SSRF 区别
PHP 支持的协议
·file:// — Accessing local filesystem
·http:// — Accessing HTTP(s) URLs
·ftp:// — Accessing FTP(s) URLs
·php:// — Accessing various I/O streams
·zlib:// — Compression Streams
·data:// — Data (RFC 2397)
·glob:// — Find pathnames matching pattern
·phar:// — PHP Archive
·ssh2:// — Secure Shell 2
·rar:// — RAR
·ogg:// — Audio streams
·expect:// — Process Interaction Streams

Java 支持的协议
·file
·ftp
·gopher
·http
·https
·jar
·mailto
·netdoc

### 宽字节注入漏洞原理、利用方式及修复方案？ (★★)

(1) 原理
php 中 gbk 编码
(2) 利用方式
使用%df 可以闭合引号
(3) 修复方案
使用 mysql_set_charset(GBK)指定字符集

### 如何设计落地一个 CSRF Token (★★★)

在请求中添加一个攻击者不知道的参数（且该参数浏览器不会自动发送），让服务端可以区别出请求是否经过用户的同意。

这样用户知道该参数，发送请求的时候，携带 cookie 和该参数；而攻击者不知道该参数，浏览器发送请求时，只自动携带了 cookie。服务端即可通过校验该参数，来判断操作是否是用户真实想进行的。

这个参数，就被称为 csrf token。

HTTP request Header: 将 token 添加在 header 中发送，它具有一个天然的优势，可以利用浏览器的同源策略：csrf token header 相当于一个自定义 header，在跨域请求时，携带自定义 header，会触发预检请求，若预检请求不通过，正式请求就不会发送。

双重提交（Double Submit Cookie）

在请求到达服务端后，服务端不需要再从数据库/缓存中读取对应的值来跟 csrf token 比对。只需要跟请求中的 csrf cookie 比对即可。这个 cookie 就是服务端当初签发出去的 token 参数。只要它们相等，就证明请求是经过用户同意发送的，因为攻击者无法读取这个 cookie 值，也就无法将这个值作为 token 参数，添加到请求中发送，而用户是知道的（用户可以读取 csrf token cookie）。
我们可以使用加密签名的方式：
将用户的 session token 作为明文，使用服务端的密钥进行加密签名，加密后的秘文作为 csrf token value 发送给客户端。使用 session token 作为明文有 2 个好处：即保证了 csrf token 跟 user 绑定，又保证了 csrf token 的随机且唯一。即：
csrf_token = HMAC(session_token, application_secret)

当服务端收到请求后，从缓存/数据库/cookie 中获取原来的加密明文 session_token，使用服务端的密钥再进行一次加密签名，比对签名后的结果 和 请求中携带的 csrf token 参数是否相等，若相等，则：
csrf token 是服务端签发的，签名的内容没有被篡改，即该 token 就是当前用户的。

### CORS 原理、利用及修复？(★★)

(1) CORS 全称是"跨域资源共享"（Cross-origin resource sharing）,Origin 源未严格，从而造成跨域问题,允许浏览器向跨源服务器，发出 XMLHttpRequest 请求

(2) Origin 为\*的时候，使用 curl 测试 CORS，

curl -H “Origin: https://evil.com” -I
(3) 设置白名单域名

### CRLF 注入原理 (★★★)

CRLF 指的是回车符(CR，ASCII 13，\r，%0d) 和换行符(LF，ASCII 10，\n，%0a)。

CRLF 注入漏洞的本质和 XSS 有点相似，攻击者将恶意数据发送给易受攻击的 Web 应用程序，Web 应用程序将恶意数据输出在 HTTP 响应头中。（XSS 一般输出在主体中）

所以 CRLF 注入漏洞的检测也和 XSS 漏洞的检测差不多。通过修改 HTTP 参数或 URL，注入恶意的 CRLF，查看构造的恶意数据是否在响应头中输出。

### Fastjson 反序列化漏洞的原理？ 几次绕过的绕过方式？ 如何彻底解决 Fastjson 漏洞？(★★★★)

(1) 原理
攻击者可以传入一个恶意构造的 JSON 内容，程序对其进行反序列化后得到恶意类并执行了恶意类中的恶意函数，进而导致代码执行。

(2) 绕过、
·fastjson-1.2.24
(fastjson 接受的 JSON 可以通过艾特 type 字段来指定该 JSON 应当还原成何种类型的对象，在反序列化的时候方便操作)

·fastjson-1.248 以下
(checkAutoType 中使用 TypeUtils.getClassFromMapping(typeName)去获取 class 不为空，从而绕过了黑名单检测)
利用解析问题可以加括号或大写 L 绕过低版本
高版本利用了哈希黑名单，找到可以绕过了类
在 1.2.47 版本中利用缓存绕过

·1.2.68 版本
1.2.68 之前的 66 和 67 可以利用 JNDI 相关类，比如 Shiro 的 JndiObjectFactory 和 ignite 项目的类
1.2.68 中有一个期望类属性，实现了期望接口的类可以被反序列化
利用类必须是 expectClass 类的子类或实现类，并且不在黑名单中，即可直接绕过 AutoType 检测，例如常见的 AutoCloseable
这样的 Payload 通常第一个@type 是 AutoCloseable 等合法类，第二个@type 是恶意类，后续参数是恶意类需要的参数

(3) 修复
·方案一：开启 safemode
适用于完全不需要 autoType 的应用。开启时，会强制关闭 autoType。

优点：最安全的方案，完全禁用 autoType，新的版本再爆出反序列化漏洞时，极大概率不需要再升级也能免疫。

不足：仅适用于完全不需要 autoType 的应用。

·方案二：配置一个 autoType 白名单。

优点：相对安全，可以避免一些恶意类的传入，前提是白名单范围要尽量缩小。新的版本再爆出反序列化漏洞时，大概率不需要再升级也能免疫。

不足：情况复杂的业务，梳理有哪些数据是需要用到 autoType 反序列化的，整理出白名单需要一定时间。

·方案三：autoType 黑名单

优点：整改成本低，处理速度快。

不足：安全性不如前两种方案，短期内可作为临时方案，缓解外部漏洞探测。有极低的概率会对已有业务产生影响（反序列化的内容里包含 java.net.前缀类型对象的情况）。

### 扫描端口遇到端口全部开放的情况怎么办? (★★)

一般是 CDN 或者防火墙的安全策略导致的

判断 CDN 1.直接基于 CNAME 判断 2.多地 ping
绕过 CDN，尝试寻找真实 IP： 1.子域名 2.利用漏洞 3.历史 DNS 记录 4.邮件源码 5.国外请求 6.查询 Https 证书

### 泛解析的域名如何进行子域名爆破？ (★★★)

首先的访问一个随机并不存在的域名 test.xx.com，记录其泛解析到的 IP 地址。
然后通过字典枚举域名的 A 记录，并与最开始的 test.xx.com 的 A 记录做对比，不同的则是存在的域名

### sqlmap 时间盲注参数 (★★)

--time-sec 设置时间盲注延迟

### xss 在 a 标签怎么利用？ (★★)

javascript 伪协议
<a href="javascript:alert(/test/)">xss</a>

### 存在注入然后数据库没有数据怎么办？(★★)

尝试写 WebShell

### PHP eval 和 system 的区别 (★★)

命令执行和代码执行的区别

### 文件上传中`%00`截断的原理是什么，官方是如何设计修复方案的?(★★)

(1) 原理：
%00 被解码为 0x00,系统在对文件名的读取时，如果遇到 16 进制的 0x00，就会认为读取已结束进行截断。
(2) 修复：
比较长度是否一样

### 介绍一下自认为有趣的挖洞经历 (★★★)

1. 挖到一个厂商子平台账号漏洞，该账号直接涉及目标厂家的所有平台，直接定级为核心严重
2. 找到一个 ssrf 接口，厂家定级中危，后通过该接口打到其内网的 redis 并 getshell,漏洞升级高危。
   。。。。。。

### CSRF 的成因及防御措施（不用 token 如何解决) (★★)

1. CSRF 主要是因为浏览器没有判断是否是用户本人操作
2. 防御一般是：  
   (1) 请求 Header 头增加随机值，服务端对随机值进行验证，验证通过服务端才允许请求成功
   (2) 增加验证码
   (3) 增加当前用户密码的验证

### 简述一下 SSRF 中 DNSRebind 的绕过原理及修复方法 (★★)

1. 原理：
   DNS 重绑定攻击，DNS 解析是有时间差,把第一次解析的 IP 设为合法 IP，就能绕过 host 合法性检查了；把第二次解析的 IP 设为内网 IP，就达到了 SSRF 访问内网的目的

2. 修复方法：
   (1) DNS 安全代理
   (2) 第三方 DNS 服务

### CSP 应该如何使用及配置，有哪些绕过 CSP 的方式 (★★)

> CSP（Content Security Policy，内容安全策略）

- 利用跳转功能绕过 location.href
- link 标签预加载绕过
- meta 网页跳转绕过
- iframe 绕过
- CDN 绕过（CDN 存在低版本的框架）
- 不完整的 script 标签绕过
- 302 重定向绕过

### 简述一下 XXE 漏洞产生的原理，针对 PHP 和 JAVA，XXE 分别可以进行哪些恶意利用?(★★)

1. 原理：

当 应用允许引用 XML 外部实体时，攻击者通过构造恶意内容，就可能进行任意文件读取、系统命令执行、内网端口探测、内网网站攻击等操作

### JWT 相较于 SESSION 优劣势？ (★★★)

(1) 区别：
seesion 保存在服务端
jwt 保存在客户端
(2) 优劣势:

· jwt 优点：
可拓展性好
无状态

· jwt 缺点：
安全性
性能
一次性：
无法废弃
续签
