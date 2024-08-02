# Network Monitoring Script

Этот скрипт предназначен для мониторинга сетевых устройств и отслеживания веб-сайтов, которые посещают подключенные устройства. Он использует библиотеки `scapy` и `colorama` для анализа сетевых пакетов и цветного вывода информации в консоль.

## Требования

Для запуска скрипта вам понадобятся следующие библиотеки Python.
Вы можете установить их с помощью файла `requirements.txt`:

```bash
pip install -r requirements.txt
```

# Описание скрипта
## Инициализация
В начале скрипта создаются словарь для хранения подключенных устройств (`connected_devices`) и пути к файлам для хранения данных о подключенных устройствах (`connected_devices.json`) и веб-запросах (`web_search`).

## Функция save_to_json
Эта функция сохраняет переданные данные в JSON файл. Если возникает ошибка при сохранении, она выводит сообщение об ошибке.

## Функция get_device_name
Эта функция получает имя устройства по его IP адресу, используя функцию `socket.gethostbyaddr`. Если имя устройства не удается определить, возвращается строка "unknown".

## Обработчик ARP пакетов handle_arp_packet
Эта функция обрабатывает ARP пакеты, извлекая MAC адрес и IP адрес устройства. Если устройство новое (MAC адрес не найден в словаре `connected_devices`), оно добавляется в словарь. Если данные устройства обновились, словарь также обновляется. Изменения сохраняются в файл connected_devices.json.

## Функция обратного вызова packet_callback
Эта функция вызывается для каждого захваченного сетевого пакета. Она проверяет, является ли пакет ARP или DNS, и вызывает соответствующие обработчики.

## Запуск прослушивания сетевых пакетов
Скрипт запускает прослушивание сетевых пакетов с помощью функции `sniff` из библиотеки `scapy`. Все захваченные пакеты обрабатываются функцией `packet_callback`.

## Запуск скрипта
Для запуска скрипта используйте следующую команду:
```python
python main.py
```
Скрипт начнет прослушивание сетевых пакетов и будет выводить информацию о новых и обновленных устройствах, а также о посещенных веб-сайтах.
