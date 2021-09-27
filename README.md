# Docker Container With pgBench

pgbench is a simple program for running benchmark tests on PostgreSQL.

https://www.postgresql.org/docs/10/pgbench.html

## Build
```bash
docker build -t mattdevdba/pgbench .
```

## Vairables
See env.list and ensure the correct values are set for your database before running

## Initialize
```bash
docker run -it --env-file ./env.list mattdevdba/pgbench pgbench -i
```

## Run Example - 10k Transactions, 10 Clients, 10 Threads
```bash
docker run -it --env-file ./env.list mattdevdba/pgbench pgbench -c 10 -j 10 -t 10000
```

## Docker Hub
https://hub.docker.com/r/mattdevdba/pgbench
