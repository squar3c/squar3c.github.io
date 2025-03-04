---
title: 信息收集(TODO)
tags:
  - 网络安全
hide: false
abbrlink: 56033
date: 2025-03-03 23:25:57
---



# 信息收集

> 信息收集是渗透测试中的第一步，也是最为关键的一步。有大佬说过：渗透测试的本质就是信息收集。因此在这里认真钻研一下信息收集部分，包括收集什么？如何收集？自动化工具的原理？也尽量自己在每个模块开发出自己的工具，最终整合成自己的信息收集工具。

## 域名（Domain）

> 域名是由一串用点分隔的字符组成的互联网上某一台计算机或计算机组的名称，用于在数据传输时标识计算机的电子方位。域名是IP地址的代称，目的是便于记忆。一般渗透都会从一个域名开始，因此由域名开始作为切入口。

### 判断CDN

内容分发网络（Content Delivery Network）的基本思路是尽可能避开互联网上有可能影响数据传输速度和稳定性的瓶颈和环节，使内容传输更快更稳定。那这对我们渗透测试带来了什么影响呢？

CDN会代理客户端的请求，将真实服务器的IP地址隐藏，让我们无法直接定位目标服务器，因此需要绕过CDN。

**ping域名判断是否有CDN**

当ping出来的域名为很长一串字符，或者有着很明显的cdn、ali、tencent等字段时大概率存在CDN。

![img](https://cdn.jsdelivr.net/gh/Squarehhh/DrawingBed/myblog/20241121133118.png)

**nslookup判断CDN**

nslookup是一个命令行工具，用于查询Internet域名信息或诊断DNS服务器问题。

通过nslookup检测一个域名是否对应多个IP可以判断是否使用CDN

![img](https://cdn.jsdelivr.net/gh/Squarehhh/DrawingBed/myblog/20241121133620.png)

**多地ping判断CDN**

[站长工具](https://ping.chinaz.com/)还是比较直观的

![img](https://cdn.jsdelivr.net/gh/Squarehhh/DrawingBed/myblog/20241121133805.png)

### 查看真实IP

检测完CDN，就该绕过CDN检测了，获取真实IP

**多地ping**

不仅是检测CDN，同时也可以用来判断。

如`www.youzan.com`，可以发现存在CDN，但是发现在除中国大陆外都是同一个IP，因此可以判断为真实IP

![img](https://cdn.jsdelivr.net/gh/Squarehhh/DrawingBed/myblog/20241121134240.png)

**子域名查询真实IP**

CDN并非免费的，成本较大，因此很多公司可能只对主站或者访问量较大的站做了CDN加速。因此可以通过获取子域名来查询真实IP，查询方式可以利用上述多地ping方法。子域名收集在后面单独讲。

**DNS历史记录**

查看IP与域名绑定的历史记录，可能存在使用CDN前的解析记录，[Viewdns](https://viewdns.info/)或者之前的开发工具都可以查询

**SSL证书**

加入web服务器支持SSL并具有证书，在端口443直接访问时，SSL证书就会被暴露。此时攻击者会看见一个使用特定证书的IPv4主机列表，真实IP就在其中。

**漏洞查找**

- 敏感文件泄露，如phpinfo等，github信息泄露等。
- XSS、命令执行、SSRF等。
- 社工等手段，拿到目标管理员在CDN账号，可以在CDN配置找到。

**网站邮件**

很多网站都自带`sendmail`，会发邮件给我们，此时查看邮件源码里面就会包含服务器的真实IP

**F5 LTM解码**

当服务器使用FT5 LTM做负载均衡的时候，对set-cookie关键字解码也可以获取真实IP

```
Set-Cookie: BIGipServerpool_8.29_8030=487098378.24095.0000
先把第一小节的十进制数取出来：487098378
再转化为十六进制数：1d08880a
从后至前取四位数：0a.88.08.1d
转化为十进制即为IP：10.136.8.29
```

### 子域名收集

在前面查看真实IP的地方提到了子域名收集，子域名收集不只是为了找真实IP服务，更是为了扩大资产收集范围。

**搜索引擎收集**

使用谷歌语法等可以收集大量信息，如`site:domain`

![img](https://cdn.jsdelivr.net/gh/Squarehhh/DrawingBed/myblog/20241121143338.png)

尝试自己写了个基于Chrome搜索的脚本，爬取效果还是不错的，后面看看能不能增加功能

```python
import argparse
import re
import signal
import sys

from selenium import webdriver
from selenium.webdriver.common.by import By


# write to file
def write_file(file_path, content):
    try:
        with open(file_path, 'a', encoding='utf-8') as file:
            file.write(content + '\n')
        return True
    except Exception as e:
        print(e)
        return False


# signal handler
def signal_handler(sig, frame):
    print("\nuser pause")
    sys.exit(0)


# init selenium
def setup_driver():
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    return webdriver.Chrome(options=options)


# get domain in links
def extract_domain(link):
    match = re.search(r"https://(.*?)/", link)
    if match:
        return match.group(1)
    return None


# fetch links from result
def fetch_links(driver, domain, page):
    url = f"https://www.google.com/search?q=site:{domain}&start={page}0"
    driver.get(url)

    try:
        elements = driver.find_elements(By.CSS_SELECTOR, "#rso .kb0PBd.A9Y9g.jGGQ5e span > a")
        links = []
        for element in elements:
            link = element.get_attribute("href")
            if link:
                links.append(link)
        return links
    except Exception as e:
        print(f"failed to fetch links: {e}")
        return []


# main
def main():
    # signal init
    signal.signal(signal.SIGINT, signal_handler)

    # parse user input
    parser = argparse.ArgumentParser(description="Chrome search script")
    parser.add_argument("-d", "--domain", required=True, help="The domain to search")
    parser.add_argument("-m", "--maxpage", type=int, required=True, help="The maximum number to search")
    args = parser.parse_args()

    # parameter assignment
    domain = args.domain
    max_page = args.maxpage

    # init driver
    driver = setup_driver()

    # remove duplicates
    unique_links = set()

    # Start crawling from the first page
    for page in range(0, max_page + 1):
        links = fetch_links(driver, domain, page)

        # Traverse links, extract and save unique domain names
        for link in links:
            domain_name = extract_domain(link)
            if domain_name and domain_name not in unique_links:
                unique_links.add(domain_name)
                print(domain_name)
                write_file("domain.txt", domain_name)

    # close driver
    driver.quit()


if __name__ == "__main__":
    main()
```

**资产测绘工具搜集**

使用资产测绘工具收集，如**fofa、hunter、360quake、微步**等，包括使用站长之家等等。

![img](https://cdn.jsdelivr.net/gh/Squarehhh/DrawingBed/myblog/20241122163631.png)

**使用自动化工具**

这里对两种开源的工具进行源码分析，了解其原理

#### **SubDomainBrute源码分析**

这里只分析主要代码

```python
# 加载DNS服务器地址
def load_dns_servers():
    print_msg('[+] Validate DNS servers', line_feed=True)
    dns_servers = []

    servers_to_test = []
    # 从字典中加载未被注释的DNS服务器地址
    for server in open(os.path.join(root_path, 'dict/dns_servers.txt')).readlines():
        server = server.strip()
        if server and not server.startswith('#'):
            servers_to_test.append(server)

	# 异步验证DNS服务器，dns_servers为传入的空列表，保存验证通过的DNS服务器地址
    loop = asyncio.get_event_loop()
    loop.run_until_complete(async_load_dns_servers(servers_to_test, dns_servers))

    # 打印有效DNS服务器地址
    server_count = len(dns_servers)
    print_msg('\n[+] %s DNS Servers found' % server_count, line_feed=True)
    if server_count == 0:
        print_msg('[ERROR] No valid DNS Server !', line_feed=True)
        sys.exit(-1)
    return dns_servers

# 加载子域名爆破字典
def load_next_sub(full_scan):
    next_subs = []
    # 根据full_scan参数判断加载哪个字典
    _file = 'dict/next_sub_full.txt' if full_scan else 'dict/next_sub.txt'
    
    # 将子域名去重后存入临时集合tmp_set
    with open(os.path.join(root_path, _file)) as f:
        for line in f:
            sub = line.strip()
            if sub and sub not in next_subs:
                tmp_set = {sub}
                
                # 如果子域名模块包含占位符，如{alphnum}，则进行替换操作
                while tmp_set:
                    item = tmp_set.pop()
                    if item.find('{alphnum}') >= 0:
                        for _letter in 'abcdefghijklmnopqrstuvwxyz0123456789':
                            tmp_set.add(item.replace('{alphnum}', _letter, 1))
                    elif item.find('{alpha}') >= 0:
                        for _letter in 'abcdefghijklmnopqrstuvwxyz':
                            tmp_set.add(item.replace('{alpha}', _letter, 1))
                    elif item.find('{num}') >= 0:
                        for _letter in '0123456789':
                            tmp_set.add(item.replace('{num}', _letter, 1))
                    elif item not in next_subs:
                        next_subs.append(item)
    return next_subs
```

加载字典的功能中，使用占位符的方式让这个工具更加灵活，字典文件更加通用，并且通过这个方式可以轻松生成大规模的子域名。

在子域名中还存在一个**泛解析**的问题，这个工具里面解决了这个问题

```python
async def async_wildcard_test(domain, dns_servers, level=1):
    try:
        # 创建异步DNS解析器
        r = dns.asyncresolver.Resolver()
        # 使用DNS服务器解析域名
        r.nameservers = dns_servers
        # 使用异步DNS查询解析A记录，lijiejie-not-existed-test是一个随机的子域名，理论上不存在
        answers = await r.resolve('lijiejie-not-existed-test.%s' % domain, 'A', lifetime=10)
        # 如果解析成功，讲这些IP手机在ips中，如果解析的IP有效，可能意味着域名启用了通配符解析
        ips = ', '.join(sorted([answer.address for answer in answers]))
        # 初步检测，生成一个子域名，并递归调用进一步检测，并将level设置为2
        if level == 1:
            print('any-sub.%s\t%s' % (domain.ljust(30), ips))
            await async_wildcard_test('any-sub.%s' % domain, dns_servers, 2)
        # 打印提示信息，使用-w参数强制扫描通配符域名
        elif level == 2:
            print('\nUse -w to enable force scan wildcard domain')
            sys.exit(0)
    except Exception as e:
        return domain

def wildcard_test(domain, dns_servers):
    # 获取当前的异步事件循环
    loop = asyncio.get_event_loop()
    # 等待异步任务完成
    return loop.run_until_complete(
        # 并行执行多个异步任务，并返回它们的结果
        asyncio.gather(
            async_wildcard_test(domain, dns_servers, level=1)
        )
    )[0]
```

通过给出一个不存在的域名检测，判断是否开启了泛解析

接下来看看扫描模块

```python
# 爆破模块
class SubNameBrute(object):
    # 初始化
    def __init__(self, *params):
        # 提取传入参数
        self.domain, self.options, self.process_num, self.dns_servers, self.next_subs, \
            self.scan_count, self.found_count, self.queue_size_array, tmp_dir = params
        self.dns_count = len(self.dns_servers)
        self.scan_count_local = 0
        self.found_count_local = 0
        # 初始化DNS解析器
        self.resolvers = [dns.asyncresolver.Resolver(configure=False) for _ in range(self.options.threads)]
        for r in self.resolvers:
            # 解析事件
            r.lifetime = 6.0
            # 超时时间
            r.timeout = 10.0
        # 优先队列和状态变量
        self.queue = PriorityQueue()
        self.ip_dict = {}
        self.found_subs = set()
        self.cert_subs = set()
        self.timeout_subs = {}
        self.no_server_subs = {}
        self.count_time = time.time()
        # 输出日志到文件
        self.outfile = open('%s/%s_part_%s.txt' % (tmp_dir, self.domain, self.process_num), 'w')
        self.normal_names_set = set()
        self.lock = asyncio.Lock()
        # 线程状态
        self.threads_status = ['1'] * self.options.threads

    # 加载子域名字典
    async def load_sub_names(self):
        normal_lines = []
        wildcard_lines = []
        wildcard_set = set()
        regex_list = []
        lines = set()
        # 打开文件逐行读取子域名，跳过空行或重复子域名
        with open(self.options.file) as inFile:
            for line in inFile.readlines():
                sub = line.strip()
                if not sub or sub in lines:
                    continue
                lines.add(sub)

                # 判断子域名是否含占位符
                brace_count = sub.count('{')
                if brace_count > 0:
                    wildcard_lines.append((brace_count, sub))
					# 占位符处理
                    sub = sub.replace('{alphnum}', '[a-z0-9]')
                    sub = sub.replace('{alpha}', '[a-z]')
                    sub = sub.replace('{num}', '[0-9]')
                    # 去重
                    if sub not in wildcard_set:
                        wildcard_set.add(sub)
                        regex_list.append('^' + sub + '$')
                else:
                    # 普通子域名直接加入列表
                    normal_lines.append(sub)
                    self.normal_names_set.add(sub)

        if regex_list:
            pattern = '|'.join(regex_list)
            _regex = re.compile(pattern)
            for line in normal_lines:
                if _regex.search(line):
                    normal_lines.remove(line)
		
        # 普通子域名加入队列，优先级为0
        for _ in normal_lines[self.process_num::self.options.process]:
            await self.queue.put((0, _))    # priority set to 0
        
        # 含占位符的子域名直接加入队列
        for _ in wildcard_lines[self.process_num::self.options.process]:
            await self.queue.put(_)

    # 检测进程状态
    async def update_counter(self):
        while True:
            if '1' not in self.threads_status:
                return
            self.scan_count.value += self.scan_count_local
            self.scan_count_local = 0
            self.queue_size_array[self.process_num] = self.queue.qsize()
            if self.found_count_local:
                self.found_count.value += self.found_count_local
                self.found_count_local = 0
            self.count_time = time.time()
            await asyncio.sleep(0.5)

    # 检测目标域名的SSL/TLS证书的扩展信息，提取符合条件的子域名
    async def check_https_alt_names(self, domain):
        try:
            # 建立异步HTTPS连接
            reader, _ = await asyncio.open_connection(
                host=domain,
                port=443,
                ssl=True,
                server_hostname=domain,
            )
            # 获取证书详细信息
            for item in reader._transport.get_extra_info('peercert')['subjectAltName']:
                if item[0].upper() == 'DNS':
                    name = item[1].lower()
                    # 筛选符合条件的子域名
                    if name.endswith(self.domain):
                        sub = name[:len(name) - len(self.domain) - 1]    # new sub
                        sub = sub.replace('*', '')
                        sub = sub.strip('.')
                        # 去重并添加到任务队列
                        if sub and sub not in self.found_subs and \
                                sub not in self.normal_names_set and sub not in self.cert_subs:
                            self.cert_subs.add(sub)
                            await self.queue.put((0, sub))
        except Exception as e:
            pass


    # 查询DNS解析结果，并限制查询的超时时间
    async def do_query(self, j, cur_domain):
        async with timeout(10.2):
            return await self.resolvers[j].resolve(cur_domain, 'A')

    # 扫描
    async def scan(self, j):
        # 设置DNS解析器
        self.resolvers[j].nameservers = [self.dns_servers[j % self.dns_count]]
        if self.dns_count > 1:
            while True:
                s = random.choice(self.dns_servers)
                if s != self.dns_servers[j % self.dns_count]:
                    self.resolvers[j].nameservers.append(s)
                    break
        empty_counter = 0
        
        # 处理子域
        while True:
            try:
                brace_count, sub = self.queue.get_nowait()
                self.threads_status[j] = '1'
                empty_counter = 0
            except asyncio.queues.QueueEmpty as e:
                empty_counter += 1
                if empty_counter > 10:
                    self.threads_status[j] = '0'
                if '1' not in self.threads_status:
                    break
                else:
                    await asyncio.sleep(0.1)
                    continue

            # 对于带有通配符的子域进行处理
            if brace_count > 0:
                brace_count -= 1
                if sub.find('{next_sub}') >= 0:
                    for _ in self.next_subs:
                        await self.queue.put((0, sub.replace('{next_sub}', _)))
                if sub.find('{alphnum}') >= 0:
                    for _ in 'abcdefghijklmnopqrstuvwxyz0123456789':
                        await self.queue.put((brace_count, sub.replace('{alphnum}', _, 1)))
                elif sub.find('{alpha}') >= 0:
                    for _ in 'abcdefghijklmnopqrstuvwxyz':
                        await self.queue.put((brace_count, sub.replace('{alpha}', _, 1)))
                elif sub.find('{num}') >= 0:
                    for _ in '0123456789':
                        await self.queue.put((brace_count, sub.replace('{num}', _, 1)))
                continue

            try:
                if sub in self.found_subs:
                    continue

                self.scan_count_local += 1
                cur_domain = sub + '.' + self.domain

                # 执行DNS查询
                answers = await self.do_query(j, cur_domain)
                
                # 处理DNS查询结果，排除无效IP
                if answers:
                    self.found_subs.add(sub)
                    ips = ', '.join(sorted([answer.address for answer in answers]))
                    invalid_ip_found = False
                    for answer in answers:
                        if answer.address in ['1.1.1.1', '127.0.0.1', '0.0.0.0', '0.0.0.1']:
                            invalid_ip_found = True
                    if invalid_ip_found:
                        continue
                    if self.options.i and is_intranet(answers[0].host):
                        continue

                    try:
                        # 查询CNAME记录
                        cname = str(answers.canonical_name)[:-1]
                        if cname != cur_domain and cname.endswith(self.domain):
                            cname_sub = cname[:len(cname) - len(self.domain) - 1]    # new sub
                            if cname_sub not in self.found_subs and cname_sub not in self.normal_names_set:
                                await self.queue.put((0, cname_sub))
                    except Exception as e:
                        pass

                    first_level_sub = sub.split('.')[-1]
                    max_found = 20

                    if self.options.w:
                        first_level_sub = ''
                        max_found = 3

                    if (first_level_sub, ips) not in self.ip_dict:
                        self.ip_dict[(first_level_sub, ips)] = 1
                    else:
                        self.ip_dict[(first_level_sub, ips)] += 1
                        if self.ip_dict[(first_level_sub, ips)] > max_found:
                            continue

                    self.found_count_local += 1

                    # 将查询结果写入文件
                    self.outfile.write(cur_domain.ljust(30) + '\t' + ips + '\n')
                    self.outfile.flush()

                    # 检查HTTPS证书
                    if not self.options.no_cert_check:
                        async with timeout(10.0):
                            await self.check_https_alt_names(cur_domain)

                    try:
                        self.scan_count_local += 1
                        await self.do_query(j, 'lijiejie-test-not-existed.' + cur_domain)

                    except dns.resolver.NXDOMAIN as e:
                        if self.queue.qsize() < 20000:
                            for _ in self.next_subs:
                                await self.queue.put((0, _ + '.' + sub))
                        else:
                            await self.queue.put((1, '{next_sub}.' + sub))
                    except Exception as e:
                        continue

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
                pass
            except dns.resolver.NoNameservers as e:
                self.no_server_subs[sub] = self.no_server_subs.get(sub, 0) + 1
                if self.no_server_subs[sub] <= 3:
                    await self.queue.put((0, sub))    # Retry again
            except (dns.exception.Timeout, dns.resolver.LifetimeTimeout) as e:
                self.timeout_subs[sub] = self.timeout_subs.get(sub, 0) + 1
                if self.timeout_subs[sub] <= 3:
                    await self.queue.put((0, sub))    # Retry again
            except Exception as e:
                if str(type(e)).find('asyncio.exceptions.TimeoutError') < 0:
                    with open('errors.log', 'a') as errFile:
                        errFile.write('[%s] %s\n' % (type(e), str(e)))

    async def async_run(self):
        await self.load_sub_names()
        tasks = [self.scan(i) for i in range(self.options.threads)]
        tasks.insert(0, self.update_counter())
        await asyncio.gather(*tasks)

    def run(self):
        loop = asyncio.get_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.async_run())

def run_process(*params):
    # 信号处理器
    signal.signal(signal.SIGINT, user_abort)
    # 调用SubNameBrute的run方法
    s = SubNameBrute(*params)
    s.run()

# 根据option.process启动多个进程
for process_num in range(options.process):
    p = multiprocessing.Process(
        # 调用run_process进行扫描
        target=run_process,
        args=(domain, options, process_num, dns_servers, next_subs,
              scan_count, found_count, queue_size_array, tmp_dir)
    )
    all_process.append(p)
    p.start()
```

总体的工作路径为：

- **加载子域名**：从文件中读取子域名，识别通配符，放入任务队列
- 扫描子域
  - 多线程扫描子域
  - 对每个子域执行DNS查询，处理返回结果
  - 对子域名进行证书检查，CNAME解析等附加操作
- **记录结果**
- **错误处理与重试**：对于DNS查询失败的子域进行重试，最多三次

这里有个证书检查和CNAME解析，还有一个称呼叫**证书透明度**主要原因是**提高全面性**。在**SSL/TLS**证书中的`subjectAltName`字段会暴露一些隐藏子域。**CNAME**是DNS中的一种记录类别，通常用于将一个域名指向另一个域名，也就是说CNAME可以为某个域名创建一个别名，因此可以去发现隐藏的域名，增加子域名查询的全面性。

**对于通配符子域名的处理**：讲这些子域存在一个集合中，避免重复爆破，根据查询CNAME和MX记录，挖掘更多的子域，并且进行递归查询。
