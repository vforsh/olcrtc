# Протокол OLC3

OLC3 - несовместимый переход с прежнего формата. Он использует метку записи
`OLC3`, протокол рукопожатия 4 и протокол управления 2. Старые клиенты и серверы
должны завершать соединение с безопасной типизированной ошибкой.

## Рукопожатие 4

После установки PSK-шифрованного mux-соединения клиент отправляет
`CLIENT_HELLO` со случайным 16-байтовым challenge. Успешный сервер отвечает
`SERVER_HELLO`, повторяя challenge и передавая только безопасную идентичность:

```json
{"version":4,"type":"SERVER_HELLO","challenge":"<32 hex>","session_id":"<opaque>","peer_id":"<routing id>","server":{"wire":"OLC3","build":"<40 lowercase hex>","profile_id":"<uuid>","current_profile_revision":2,"minimum_profile_revision":1,"endpoint_id":"jitsi-primary","capabilities":["server-hello-v1","notice-v1","drain-v1"]},"availability":{"state":"ready","reason":"none"}}
```

Клиент обязан проверить challenge, wire, build, profile ID, endpoint ID, окно
ревизий и все обязательные capabilities до открытия SOCKS-трафика. Свободный
текст от удалённой стороны не показывается. Отказ имеет тип `SERVER_REJECT` и
один из фиксированных кодов: `malformed`, `protocol_version`, `unauthorized`,
`server_unavailable`, `incompatible`.

JSON с повторяющимися или неизвестными полями, хвостовыми значениями и
превышением размера кадра отклоняется.

## Управление 2

Ping, pong и close сохраняют прежнюю семантику, но используют version 2.
Сервер может отправить типизированное уведомление:

```json
{"version":2,"type":"CONTROL_NOTICE","sequence":7,"state":"draining","reason":"maintenance","retry_after_seconds":300}
```

`sequence` строго возрастает. Состояния: `ready`, `draining`, `unavailable`.
Причины: `none`, `maintenance`, `overloaded`, `retiring`, `incompatible`.

CLI-сервер ставит `draining/retiring` в очередь по `SIGUSR1`, а
`unavailable/maintenance` по `SIGUSR2`. Остановка остаётся на `SIGTERM`.
Сигналы не несут строк или секретов; порядковый номер назначает сам процесс.
`retry_after_seconds` находится в диапазоне 0…86400. После `unavailable`
возврат к другому состоянию в той же сессии запрещён. Очередь ping/pong имеет
приоритет над уведомлениями, чтобы уведомления не ломали проверку живости.

Ни один кадр не содержит host, room, PSK, SOCKS-реквизиты, внешний IP или путь
на сервере.
