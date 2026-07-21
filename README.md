# 🏋️ Monster Fitness — Sistema Web Completo

> Stack: Python · Flask · MySQL · Nginx · Docker Compose  
> Segurança: bcrypt · JWT · CSRF · Rate Limiting · Security Headers  

---

## Arquitetura da Infraestrutura

```
                         INTERNET
                             │
                    ┌────────▼────────┐
                    │     NGINX       │  ← Proxy Reverso
                    │   porta :80     │    Rate Limiting
                    │   (mf_nginx)    │    Cache Estático
                    └────────┬────────┘    Headers de Segurança
                             │
              ┌──────────────┼──────────────┐
              │              │              │
         /static/        /api/*         /  (páginas)
              │              │              │
         Servido pelo    ┌───▼──────────────▼───┐
         Nginx diret.    │     FLASK API        │  ← Backend Python
                         │     porta :5000      │    JWT Auth
                         │     (mf_api)         │    CSRF Protection
                         └───────────┬──────────┘    Validação/Sanitização
                                     │
                          ┌──────────▼──────────┐
                          │       MYSQL 8.0     │  ← Banco de Dados
                          │       porta :3306   │    Não exposto externamente
                          │       (mf_db)       │    Volume persistente
                          └─────────────────────┘
```

## Função de cada camada

| Camada | Container | Responsabilidade |
|--------|-----------|-----------------|
| **Front-end** | mf_nginx | Serve HTML/CSS/JS. Bootstrap 5 + design responsivo mobile-first |
| **Proxy Reverso** | mf_nginx | Roteia requisições, aplica rate limiting, cache de estáticos, headers de segurança |
| **API Backend** | mf_api | Lógica de negócio, autenticação JWT, CSRF, validação de dados, geração de treinos |
| **Banco de Dados** | mf_db | Armazena usuários, sessões, tokens CSRF. Isolado na rede interna |

---

## Funcionalidades

- ✅ Cadastro de clientes (3 passos: dados pessoais → acesso → plano/objetivo)
- ✅ Login com JWT em cookie httpOnly
- ✅ Dashboard com personal trainer indicado e treino gerado automaticamente
- ✅ Geração aleatória de treino por objetivo (hipertrofia, emagrecimento, condicionamento, força, saúde, funcional)
- ✅ Edição de perfil / matrícula
- ✅ Delete de conta com confirmação de senha (soft delete)
- ✅ Logout com revogação de sessão no banco

## Segurança (nível Intermediário)

| Mecanismo | Implementação |
|-----------|--------------|
| Senhas | bcrypt rounds=12 |
| Autenticação | JWT com JTI armazenado e revogável |
| CSRF | Token de uso único em tabela |
| Rate Limiting | Flask-Limiter + Nginx `limit_req_zone` |
| Headers | X-Frame-Options, CSP, X-Content-Type-Options, etc. |
| SQL Injection | Queries parametrizadas (mysql.connector) |
| XSS | Sanitização de inputs + CSP header |
| Dados sensíveis | DB não exposto externamente; senha nunca retorna na API |

---

## Como executar

### Pré-requisitos
- Docker + Docker Compose instalados

### 1. Configurar variáveis de ambiente

```bash
cp .env.example .env
# Edite .env com suas senhas seguras
```

### 2. Subir o ambiente

```bash
docker compose up --build -d
```

### 3. Verificar saúde

```bash
curl http://localhost/health
# {"status": "ok", "db": true}
```

### 4. Acessar

- Site: http://localhost
- Health: http://localhost/health

---

## Análise de tráfego com Wireshark

### Instalação
```bash
# Ubuntu/Debian
sudo apt install wireshark
```

### Captura de tráfego da aplicação

```bash
# 1. Descobrir a interface de rede do container Docker
docker network inspect monster-fitness_mf_net

# 2. Capturar tráfego na interface br- (bridge Docker)
sudo wireshark -i br-<NETWORK_ID> -k

# Ou via tcpdump (salva para abrir no Wireshark)
sudo tcpdump -i br-<NETWORK_ID> -w monster_traffic.pcap
```

### Filtros úteis no Wireshark

```
# Ver todo tráfego HTTP entre Nginx e Flask
http

# Ver requisições de login
http.request.uri contains "/api/login"

# Ver tráfego entre Flask e MySQL (porta 3306)
tcp.port == 3306

# Ver apenas tráfego do container API
ip.addr == 172.x.x.x
```

### O que observar
- **Nginx → Flask**: Requisições HTTP/1.1 com headers X-Real-IP, X-Forwarded-For
- **Flask → MySQL**: Protocolo MySQL Wire (porta 3306) — queries parametrizadas
- **Cliente → Nginx**: Cookies httpOnly nas respostas (mf_token)
- **Rate limiting**: Respostas 429 após exceder limite

---

## Estrutura do projeto

```
monster-fitness/
├── app.py                  ← Backend Flask completo
├── Dockerfile              ← Build da API
├── docker-compose.yml      ← Orquestração completa
├── requirements.txt        ← Dependências Python
├── docker/
│   ├── nginx.conf          ← Proxy reverso configurado
│   └── init.sql            ← Schema MySQL (auto-executado)
├── static/
│   ├── css/main.css        ← Design system (preto/verde/branco)
│   └── js/main.js          ← Animações e navbar
└── templates/
    ├── index.html          ← Landing page completa
    ├── login.html          ← Login com CSRF
    ├── cadastro.html       ← Cadastro 3 passos
    ├── dashboard.html      ← Dashboard + personal + treino
    └── matricula.html      ← Edição de perfil
```

---

## Rotas da API

| Método | Rota | Auth | Descrição |
|--------|------|------|-----------|
| GET | `/api/csrf-token` | ❌ | Gera token CSRF |
| POST | `/api/cadastro` | ❌ | Cria conta |
| POST | `/api/login` | ❌ | Autenticação |
| POST | `/api/logout` | ✅ | Encerra sessão |
| GET | `/api/me` | ✅ | Dados do usuário |
| PUT | `/api/me/update` | ✅ | Atualiza perfil |
| DELETE | `/api/delete-account` | ✅ | Exclui conta |
| GET | `/api/personal/meu` | ✅ | Personal + treino do dia |
| GET | `/api/treino/novo` | ✅ | Novo treino aleatório |
| GET | `/health` | ❌ | Health check |

