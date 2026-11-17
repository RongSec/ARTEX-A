# artex 镜像（自带 LibreOffice + 仿宋/黑体/宋体/Times）

```bash
cp docker/.env.example docker/.env        # 首次：填数据库密码与初始密码
docker compose -f docker/docker-compose.yml up -d --build
docker compose -f docker/docker-compose.yml logs -f artex
docker compose -f docker/docker-compose.yml up -d   # 改完 docker/.env 后重启生效
```
