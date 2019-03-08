# Certbot with aliyun dns API support

## docker image

`kaiserli/certbot-aliyun:latest`

## build

docker-compose build certbot-aliyun

## run

``` shell
docker-compose run certbot-aliyun certonly --dns-aliyun --dns-aliyun-credentials /secret/aliyun.ini 
```

aliyun.ini example

``` env
dns_aliyun_access_key_id=xxxx
dns_aliyun_access_key_secret=xxxx
```