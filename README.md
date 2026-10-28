# DonationAlerts Provider — плагин OBS

Нативный плагин OBS Studio для Windows x64 на C++. Локальный API запускается внутри OBS; Node.js и отдельный сервер не нужны.

## Подготовка окружения

Требуются OBS Studio 32.2.2 x64, Visual Studio 2022 с компонентом «Разработка классических приложений на C++», Windows SDK 10.0.26100 и CMake 3.28 или новее.

Из корневой папки проекта запустите в PowerShell:

```powershell
.\tools\prepare-obs-sdk.ps1
```

Скрипт загружает официальный архив исходников OBS, проверяет SHA-256, настраивает CMake и собирает библиотеки `libobs` и OBS Frontend API. SDK и его зависимости остаются в игнорируемой папке `.obs-sdk`.

## Сборка и тесты

```powershell
cmake -S .\obs-plugin -B .\obs-plugin\build -G "Visual Studio 17 2022" -A "x64,version=10.0.26100.0"
cmake --build .\obs-plugin\build --config Release
ctest --test-dir .\obs-plugin\build -C Release --output-on-failure
```

Результат сборки: `obs-plugin\build\Release\donationalerts-obs-provider.dll`.

## Текущее состояние

После загрузки модуль добавляет пункт **Инструменты → Open DonationAlerts Provider** и запускает API только на `127.0.0.1:4041`. Страница управления доступна по адресу `http://127.0.0.1:4041/admin`; административный ключ выводится в журнал OBS.

Управление временными ключами:

- `GET /health`
- `GET /admin`
- `GET /api/widget-tokens`
- `POST /api/widget-tokens`
- `POST /api/widget-tokens/revoke`

Для административных запросов передавайте `X-Admin-Token`. При выпуске ключ возвращается только один раз; разрешены только read-only scope событий донатов, целей и опросов. Ключи хранятся в памяти и сбрасываются при закрытии OBS.

Это начальный этап разработки: OAuth DonationAlerts, получение профиля и истории, проверка ключа виджета при запросах данных и передача событий через WebSocket ещё не реализованы. Не открывайте локальный порт во внешнюю сеть и никому не передавайте административный ключ.
