#include <arpa/inet.h>
#include <bits/socket.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MAXSIZE 65507
#define MAXCACHE 100
// 利用宏来控制具体功能的实现
//#define PHISH
//#define USERCTL
//#define FILTER

/**
 * 用于存储请求头的部分信息
 */
struct header {
    char method[4];
    char host[1024];
    char url[1024];
};

char caches[MAXCACHE][100];

/**
 * parse 解析HTTP头
 * 
 * @buf: 需要解析的报文
 * @header: 保存相应头的结构体
 */
void parse(char *buf, struct header *header);

/**
 * 
 * @arg: 需要处理的套接字
 */
void *process(void *arg);

/**
 * init 初始化套接字
 */
int init(uint16_t port);

/**
 * 与服务器进行连接
 * 
 * @hostname: 域名
 * @port: 端口号
 * 
 * @return: 用于通信的套接字
 */
int connectTo(const char *hostname, const char *port);

/**
 * 创建新的缓存
 * 
 * @url: 缓存url，用于标识
 * @buf: 需要存储的内容
 * @cindex: 目的文件的号码
 */
void newCache(const char *url, const char *buf, int cindex);

/**
 * 获取缓存文件数量
 */
int getFileNum(const char *name);

/**
 * 依据文件号寻找缓存
 * 
 * @return: 用于读写的文件描述符
 */
int getCache(const char *url, int cindex);

/**
 *从缓存中取出Last-Modified字段中的时间
 */
void getTime(int id, char *time);

/**
 * 将缓存发送给客户端
 * 
 * @id: 标识缓存文件序号
 * @fd: 与客户端进行通信的套接字
 */
void cacheToClient(int id, int fd);

/**
 * 过滤
 * @data: 需要进行判断的数据
 * 
 * @return: 1 表示需要被过滤； 0 表示不需要
 */
int filter(const char *data, const char *rules);

/**
 * 用户过滤
 * 
 * @ip: 需要控制访问的用户ip
 * @return: 1 用户需要被过滤; 0 不需要
 */
int userCtrl(const char *ip);

/**
 * 网站引导
 * 
 * @url: 需要引导到的目的网址
 * @h: 需要被修改host的header结构体
 */
void redirect(int fd);

int cindex = 0;

int main() {
    int lfd = init(9090);
    // 获取cache目录下的缓存文件数量
    cindex = getFileNum("cache");
    if (cindex > MAXCACHE) {
        printf("缓存已经满\n");
        exit(-1);
    }
    while (1) {
        struct sockaddr_in con_addr;
        // 建立通信文件描述符
        int size = sizeof(con_addr);
        int ret = accept(lfd, (struct sockaddr *)&con_addr, &size);
        if (ret == -1) {
            if (errno == EINTR) {
                continue;
            } else {
                perror(NULL);
                exit(-1);
            }
        }
        char host[50];
        char port[5];
        // 获取来简介的客户端的域名以及端口
        inet_ntop(AF_INET, &con_addr.sin_addr.s_addr, host, sizeof(host));
        inet_ntop(AF_INET, &con_addr.sin_port, port, sizeof(port));

#ifdef USERCTL
        //用户过滤
        if (filter(host, "127.0.0.1")) {
            printf("%s 被禁止连接\n", host);
            continue;
        }
#endif

        //使用pthread 多线程技术
        pthread_t tid;
        pthread_create(&tid, NULL, process, (void *)&ret);
        //建立子线程后，与主线程进行分离
        pthread_detach(tid);
    }

    close(lfd);
    pthread_exit(NULL);
    return 0;
}

/**
 * init 初始化服务器监听套接字
 * 
 * @port: 指定监听端口
 */
int init(uint16_t port) {
    // 监听套接字
    int lfd = socket(AF_INET, SOCK_STREAM, 0);

    // 绑定
    struct sockaddr_in listen_addr;
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(port);
    bind(lfd, (struct sockaddr *)&listen_addr, sizeof(listen_addr));

    // 监听
    listen(lfd, 5);
    return lfd;
}

/**
 * 线程函数
 */
void *process(void *arg) {

    int cfd = *(int *)arg;
    char buf[MAXSIZE] = {0};
    bzero(buf, sizeof(buf));
    int count = read(cfd, buf, sizeof(buf) - 1);
    // 阻塞套接字返回值小于等于0，出现错误
    if (count <= 0) {
        close(cfd);
        pthread_exit(NULL);
    }
    char cache[count + 1];
    bzero(cache, sizeof(cache));
    memcpy(cache, buf, count);
    printf("%s", cache);
    struct header header;
    bzero(&header, sizeof(header));
    parse(cache, &header);
    printf("=====url=====\n");
    printf("%s\n", header.url);
    printf("=====Host=====\n");
    printf("%s\n", header.host);
    if (strstr(header.host, ":") != NULL) {
        close(cfd);
        pthread_exit(NULL);
    }
    int host = 0;
    char rbuf[MAXSIZE];

#ifdef FILTER
    //过滤
    if (filter(header.url, "hit")) {
        printf("%s 被禁止访问\n", header.url);
        const char forbid[] = "HTTP/1.1 403 Forbidden\r\n\r\n";
        write(cfd, forbid, sizeof(forbid));
        close(cfd);
        pthread_exit(NULL);
    }
#endif

#ifdef PHISH
    // 用户引导
    redirect(cfd);
#endif

    // 缓存相关
    int id = getCache(header.url, cindex);

    if (id == -1) { // 未进行缓存，我们访问目标服务器，将返回内容发回客户端，并将返回内容缓存
        host = connectTo(header.host, "80");
        // 转发客户端请求到目标服务器
        write(host, buf, sizeof(buf));
        cindex++;
        while (1) {
            bzero(rbuf, sizeof(rbuf));
            // 获取服务器返回
            int cnt = read(host, rbuf, sizeof(rbuf) - 1);
            if (cnt == -1) {
                perror(NULL);
            } else if (cnt == 0) {

                break;
            }
            printf("%s", rbuf);
            // 建立新缓存
            newCache(header.url, rbuf, cindex);
            // 写回客户端
            write(cfd, rbuf, sizeof(rbuf) - 1);
        }

        close(host);
        close(cfd);
        pthread_exit(NULL);
    } else { // 已进行缓存, 先进行条件get，然后决定更新或缓存
        // 打印缓存文件名
        printf("====%d====\n", id);
        bzero(cache, sizeof(cache));
        bzero(rbuf, sizeof(rbuf));

        char newreq[MAXSIZE];
        bzero(newreq, sizeof(newreq));
        memcpy(newreq, buf, strlen(buf) - 4);
        memcpy(cache, buf, strlen(buf));
        char newhead[100];

        bzero(newreq, sizeof(newreq));
        memcpy(newreq, buf, strlen(buf) - 4);
        char time[32];
        bzero(time, sizeof(time));
        // 从缓存文件中取出Last-Modified字段的时间
        getTime(id, time);
        bzero(newhead, sizeof(newhead));
        // 在新的头部添加If-Modified-Since:字段
        sprintf(newhead, "\r\nIf-Modified-Since: %s\r\n", time);
        // 新旧字段拼接
        strcat(newreq, newhead);
        printf("%s---", newreq);

        // 与上游服务器进行通信
        host = connectTo(header.host, "80");
        write(host, newreq, sizeof(newreq));
        int flag = 0;
        while (1) {
            bzero(rbuf, sizeof(rbuf));
            int cnt = read(host, rbuf, sizeof(rbuf));
            if (cnt == -1) {
                perror(NULL);
            } else if (cnt == 0) {
                break;
            }
            printf("%s", rbuf);

            // 304 时，直接将缓存文件发送给客户端
            if (strstr(rbuf, "304 Not Modified") != NULL) {
                printf("%s", rbuf);
                cacheToClient(id, cfd);
                close(host);
                break;
            } else {
                // 200 时候，我们将新的响应返回给客户端，将我们的缓存更新
                char filename[32];
                if (!flag) { // 第一次写入，将原缓存删除
                    bzero(filename, sizeof(filename));
                    sprintf(filename, "cache/%d", id);
                    remove(filename);
                    flag = 1;
                }
                // 发送客户端
                write(cfd, rbuf, sizeof(rbuf));
                // 更新
                newCache(header.url, rbuf, id);
            }
        }

        close(cfd);
        pthread_exit(NULL);
    }
}

void parse(char *buf, struct header *header) {
    printf("--------------------\n");
    //char *strtok(char *s, const char *delim);
    const char delim[] = "\r\n";
    char *token;
    token = strtok(buf, delim);
    printf("=====request line=====\n");
    printf("%s\n", token);

    if (token[0] == 'G') {
        memcpy(header->method, "GET", 4);
        memcpy(header->url, token + 4, strlen(token) - 13);
    }

    if (token[0] == 'P') {
        memcpy(header->method, "POST", 4);
        memcpy(header->url, token + 5, strlen(token) - 14);
    }

    while (token != NULL) {

        if (strstr(token, "Host") != NULL) {
            memcpy(header->host, token + 6, strlen(token) - 6);
        }
        token = strtok(NULL, delim);
    }
    printf("--------------------\n");
}

/**
 * connectTo 与服务器建立连接并返回用于通信的套接字 
 * 
 * @hostname: 服务器主机名
 * @port: 指定服务器端口
 * 
 * @return 用于与服务器通信的套接字
 * 
 */
int connectTo(const char *hostname, const char *port) {
    struct addrinfo hint, *res;
    bzero(&hint, sizeof(hint));
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;

    getaddrinfo(hostname, port, &hint, &res);
    int cfd = socket(AF_INET, SOCK_STREAM, 0);
    int ret = connect(cfd, res->ai_addr, res->ai_addrlen);
    if (ret == -1) {
        perror("connect fail");
        exit(-1);
    }

    return cfd;
}

/**
 * getFileNum() 获取路径下的文件总数
 * 
 * @name: 目录名称
 * 
 * @return: 对应路径的文件总数 
 */
int getFileNum(const char *name) {
    DIR *dir = opendir(name);
    struct dirent *ent;
    int total = 0;

    if (dir == NULL) {
        perror("can not open dir: ");
        printf("%s", name);
        exit(-1);
    }

    // 扫描所有文件，除了. 以及 ..
    while ((ent = readdir(dir)) != NULL) {
        char *dname = ent->d_name;
        if (strcmp(dname, ".") == 0 | strcmp(dname, "..") == 0) {
            continue;
        }

        if (ent->d_type == DT_REG) {
            total++;
        }
    }

    closedir(dir);
    return total;
}

/**
 * newCache 保存新的cache
 * 
 * @url: 用于标识的url
 * @buf: 需要缓存的具体报文内容
 * @id: 保存文件名
 * 
 */
void newCache(const char *url, const char *buf, int id) {
    char filename[32];
    sprintf(filename, "cache/%d", id);
    FILE *f = fopen(filename, "a");
    fprintf(f, "%s\n", url);
    fprintf(f, "%s", buf);
    fclose(f);
}

int getCache(const char *url, int cindex) {
    char filename[32];
    for (int i = 1; i <= cindex; i++) {
        bzero(filename, sizeof(filename));
        sprintf(filename, "cache/%d", i);
        FILE *f = fopen(filename, "r");
        if (f == NULL) {
            continue;
        }
        // 必须初始化
        // 详细请见: https://stackoverflow.com/questions/49740288/realloc-invalid-pointer-error-when-using-argc-and-argv
        char *line = NULL;
        size_t n = 0;
        int ret = getline(&line, &n, f);
        if (strncmp(line, url, strlen(url)) == 0) {
            return i;
        }

        fclose(f);
    }
    return -1;
}

void getTime(int id, char *time) {
    char filename[32];
    sprintf(filename, "cache/%d", id);
    FILE *f = fopen(filename, "r");
    // 逐行读取参考
    //https://stackoverflow.com/questions/3501338/c-read-file-line-by-line
    char *line = NULL;
    size_t n = 0;
    while (getline(&line, &n, f) != -1) {
        if (strstr(line, "Last-Modified:") != 0) {
            memcpy(time, strstr(line, ": ") + 2, strlen(strstr(line, ": ") + 2));
            return;
        }
    }
}

void cacheToClient(int id, int fd) {
    char filename[32];
    sprintf(filename, "cache/%d", id);
    FILE *cache;
    cache = fopen(filename, "r");

    char *line = NULL;
    size_t n = 0;
    int flag = 0;

    while (getline(&line, &n, cache) != -1) {
        if (!flag) { // ignore the first line
            flag = 1;
            continue;
        }
        write(fd, line, strlen(line));
    }
}

int filter(const char *data, const char *rules) {
    if (strstr(data, rules) != NULL) {
        return 1;
    }
}

void redirect(int fd) {
    // 重定向
    char rbuf[MAXSIZE];
    int host = 0;
    char tohost[] = "81.68.245.247";
    host = connectTo(tohost, "80");
    char data[] = "GET / HTTP/1.1\r\n\r\n";
    write(host, data, sizeof(data));
    while (1) {
        bzero(rbuf, sizeof(rbuf));
        int cnt = read(host, rbuf, sizeof(rbuf) - 1);
        if (cnt == -1) {
            perror(NULL);
        } else if (cnt == 0) {

            break;
        }
        write(fd, rbuf, sizeof(rbuf) - 1);
    }
    close(fd);
    pthread_exit(NULL);
}