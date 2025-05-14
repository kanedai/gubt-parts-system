# GUBT Parts System

GUBT Parts System是一个用于管理零部件库存的轻量级应用程序。

## 功能特点

- 用户管理（创建、编辑、删除用户）
- 管理员控制面板
- 库存查询
- 轻量级SQLite数据库

## 使用Docker运行

### 最简单的运行方式

```bash
docker run -d -p 5001:5001 -v gubt_data:/app/database --name gubt-parts-system kanedai1/gubt-parts-system:latest
```

### 使用docker-compose

```bash
# 下载docker-compose.yml
curl -O https://raw.githubusercontent.com/kanedai1/gubt-parts-system/main/docker-compose.yml

# 启动应用
docker-compose up -d
```

## 默认管理员账户

- 用户名: admin
- 密码: securepassword

您可以通过环境变量修改默认管理员账户：

```bash
docker run -d -p 5001:5001 -e ADMIN_USER=youradmin -e ADMIN_PASSWORD=yourpassword -e API_URL=http://your-api-url -v gubt_data:/app/database --name gubt-parts-system kanedai1/gubt-parts-system:latest
```

> 注意：`API_URL`环境变量用于指定后端API的URL地址，如果不指定，将使用默认值。

## 访问应用

应用运行后，访问 http://localhost:5001 即可使用。
