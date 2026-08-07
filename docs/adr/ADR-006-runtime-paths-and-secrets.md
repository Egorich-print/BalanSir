# ADR-006: Runtime Paths and Secrets

## Status

Accepted

## Context

Daemon создавал IPC-сокет в `/tmp/balansir-test/daemon.sock`, тогда как executor
и systemd-юнит `balansir.socket` уже ссылались на `/run/balansir/daemon.sock`.
Этот mismatch блокировал деплой. Кроме того, `/tmp` не защищён от других
пользователей системы: сокет без явных прав и произвольное удаление stale-файла
открывают поверхности для атаки (symlink swap, подмена сторонним процессом).

Дополнительно драйверы пишут секреты в `/tmp/balansir-<driver>-<id>.json`
с правами `0644` — читаемость всем пользователям системы (отдельная задача 1.2).

`ADR-005` уже фиксирует IPC-сокет как `/run/balansir/daemon.sock`, но daemon не
следовал этому решению.

## Decision

1. **Путь сокета** — единый `/run/balansir/daemon.sock` в daemon, executor
   и systemd. `/run` монтируется в tmpfs с `Sticky=no`, очищается на boot и
   доступен только по назначению.

2. **Права сокета**: `0600`, владелец — процесс-демона. Привязку выполняет
   сам daemon после создании родительской директории
   (`tokio::fs::create_dir_all` + `set_permissions`).

3. **Безопасное удаление stale-файла** (`remove_stale_socket`): перед bind
   удаляем существующий файл только если:
   - это сокет (`file_type().is_socket()`),
   - `st_uid` совпадает с текущим effective UID.
   В противном случае — ошибка (отказ от clobber чужого файла/symlink).

4. **Секреты драйверов** (задача 1.2): переезд с `/tmp/balansir-*` в
   `/run/balansir/<driver>-<id>.json` с `0600` и затиранием содержимого перед
   удалением.

5. **Взаимная аутентификация IPC** (задача 1.4): и server
   (`IpcServerConnection::accept`), и client (`IpcClientConnection::connect`)
   проверяют peer creds через `SO_PEERCRED`. Разрешённые UID берутся из
   `BALANSIR_ALLOWED_UIDS` (env), по умолчанию `[root]`.

6. **State Store** (задача 1.5): база (`/var/lib/balansir/state`) создаётся с
   `0700`; каждый `save` делает `fsync` файла после атомарного rename; ключи
   проходят allowlist (только `desired_state`); journal ограничен по размеру
   (`journal_capacity`) и синкается на диск.

## Consequences

- **Security**: сокет нечитаем/незаписуем для других пользователей; stale-файл
  нельзя подменить symlink'ом другого владельца.
- **Consistency**: исчезает mismatch между daemon/executor/systemd; деплой
  сходится.
- **Compatibility**: `/run` только на Linux; на macOS/дев-режиме путь остаётся
  под test-каталогом (gate через `cfg(target_os = "linux")` при необходимости).
- **Ops**: при выключении daemon сам удалит сокет; на старте — безопасно
  очистит stale от падения.

## Related

- ADR-005 (privilege separation, IPC socket).
- Milestone 1 tasks: 1.1 (socket), 1.2 (secrets), 1.3 (executor hardening).