Скрипт тестирование нагрузки на днс сервера.
cfg.yml
config:
  servers: ["8.8.8.8:53", "8.8.8.4:53"] <- список тестируемых днс серверов
  threads: 1000                         <- кол-во потоков
  request_count: 100000                 <- кол-во запросов (равномерно распределяется по всем серверам (для 1000 потоков будет 1000 * request_count)
  host: "google.com"                    <- домен для резолвинга, любой, просто чтобы делалил правильные запросы на днс сервер

Компилить: go build