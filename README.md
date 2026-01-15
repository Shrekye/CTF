# CTF

```shell
ctf-project/
│
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
│
├── ctf/
│   ├── main.py              # Interface CTF (hub)
│   ├── templates/
│   │   └── ctf_index.html
│
├── challenges/
│   ├── idor/
│   │   ├── app.py           # Challenge IDOR
│   │   ├── ctf.db
│   │   └── templates/
│   │
│   └── sqli/
│       ├── app.py           # Challenge SQLi
│       ├── challenge.db
│       └── templates/
│
└── init_db.py               # Init des DB (users, flags)
```

docker compose down -v
docker compose build --no-cache
docker compose up
