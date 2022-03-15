### 如何绕过 CDN 找到真实 IP，请列举五种方法 (★★★)

（1）子域名
（2）国外 ip 解析
（3）邮件源码
（4）查看 https 证书
（5）历史 DNS 记录

### redis 未授权访问如何利用，利用的前提条件是? (★★★)

（1）能够回连且权限够的话，写 crontab 利用计划任务执行命令反弹 shell
（2）开启 ssh 端口且权限够大的情况下，通过写公钥到服务器获得系统权限
（3）知道物理路径且 web 目录有写权限写 webshell
（4）redis 4.x 之后,主从复制 getshell,redis 是 root 权限启动的,服务器允许主从复制

### mysql 提权方式有哪些?利用条件是什么? (★)

（1）mof 提权
a: 在 windows 平台下，c:/windows/system32/wbem/mof/nullevt.mof 这个文件会每间隔一段时间（很短暂）就会以 system 权限执行一次，所以，只要我们将我们先要做的事通过代码存储到这个 mof 文件中，就可以实现权限提升。

1: mysql 用户具有 root 权限(对上面那个目录可写）
2: 关闭了 secure-file-priv

（2）udf 提权
a: UDF提权是利用MYSQL的自定义函数功能，将MYSQL账号转化为系统system权限

1: Mysql版本大于5.1版本udf.dll文件必须放置于MYSQL安装目录下的lib\plugin文件夹下。
2: Mysql版本小于5.1版本。udf.dll文件在Windows2003下放置于c:\windows\system32，在windows2000下放置于c\winnt\system32。
3: 掌握的mysql数据库的账号有对mysql的insert和delete权限以创建和抛弃函数，一般以root账号为佳，具备`root账号所具备的权限的:其它账号也可以。
4: 可以将udf.dll写入到相应目录的权限。

### windows+mysql，存在 sql 注入，但是机器无外网权限，可以利用吗? (★)
1.针对Web,增删改查
2.针对服务器，内网穿透

### 常用的信息收集手段有哪些，除去路径扫描，子域名爆破等常见手段，有什么猥琐的方法收集企业信息? (★★)
    邮箱
    网络空间搜索引擎（fofa,hunter.360quake,zoomeye)
    github获取子域名
    证书
    子域名友链
    IP反查域名
    备案
    企业APP
    企业微信公众号
    企业生活号
    企业微博
    子公司
    供应商
    天眼查API
    企查查API

### ~~SRC 挖掘与渗透测试的区别是什么，针对这两个不同的目标，实施过程中会有什么区别 (★★)。~~
低智商问题，不想回答。

### ~~存储 xss 在纯内网的环境中，可以怎么利用？(★★)~~
X崩了？蠕虫？无语的问题

### mssql 中，假设为 sa 权限，如何不通过 xp_cmdshell 执行系统命令 (★★)
1.SP_OACreate
2.沙盒
3.AgentJob

### 假设某网站存在 waf，不考虑正面绕过的前提下，应该如何绕过(分情况讨论 云 waf/物理 waf) (★)
云waf:
    寻找真实IP
物理waf：
    如果是状态跟踪型的连接检测，可以通过TTL值计算来绕过
    Nginx&Apache环境 BUG来绕过