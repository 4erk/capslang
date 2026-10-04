# Заставка только во время работы Mouse Without Borders

Отдельный пользовательский companion `CapsLangMwbSaverGuard.exe`, не новая
версия переключателя и не готовый релиз CapsLang 1.1. На ноутбуке сохраняются
установленный CapsLang 1.0 и его автозапуск.

## Поведение

- Каждые 500 мс проверяется наличие `PowerToys.MouseWithoutBorders.exe`
  **в своей Windows-сессии** через WTS; повышенные процессы не надо открывать.
- Пока MWB работает, `SPI_SETSCREENSAVEACTIVE` временно отключает только
  автоматический запуск заставки. Нет синтетического ввода, hooks и сети.
- Без `SPIF_UPDATEINIFILE`: значение в профиле не переписывается. Тайм-аут,
  пароль заставки, сон, гашение монитора и политика блокировки не меняются.
- При завершении MWB/guard прежнее состояние возвращается. Если пользователь
  изменил постоянное `ScreenSaveActive` во время работы guard, при возврате
  преимущество имеет новая настройка пользователя.
- Перед первым изменением запускается дочерний watchdog. При аварии основного
  процесса он возвращает настройку. Singleton остаётся занят до восстановления,
  исключая гонку со следующим запуском. При отказе API на заблокированной
  сессии watchdog ждёт возможности восстановить состояние.
- Guard не отключает уже запущенный `.scr`, не разблокирует Windows и
  отказывается приобретать override при политике `ScreenSaveActive`.
- При одновременном принудительном уничтожении **обоих** процессов немедленный
  возврат не гарантирован. Override непостоянный и сбрасывается при выходе из
  учётной записи. Обычная остановка — через `--stop`, а не убийство дерева.

Штатная опция MWB `BlockScreenSaverOnOtherMachines` посылает Awake только при
новом реальном вводе. Поэтому она не покрывает требование «даже когда оба
компьютера простаивают»:
[Common.SendAwakeBeat](https://github.com/microsoft/PowerToys/blob/389b1a3827b2cf577723288df15437490ef0663a/src/modules/MouseWithoutBorders/App/Core/Common.cs#L545-L563).
API: [SystemParametersInfoW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow).

## Сборка и проверка

```powershell
.\build.ps1 -SaverGuardOnly
# Opt-in: кратковременно меняет runtime-флаг заставки и возвращает его.
.\tests\windows_saver_guard.ps1 -Exe .\build\saver-guard\CapsLangMwbSaverGuard.exe
.\tools\install-mwb-saver-guard.ps1 -SourceExe .\build\saver-guard\CapsLangMwbSaverGuard.exe
```

Установка: `%LOCALAPPDATA%\CapsLang\MwbSaverGuard\CapsLangMwbSaverGuard.exe`.
Задача `CapsLang MWB Screensaver Guard`: при входе своего пользователя,
интерактивный Limited token, без UAC, без ограничения длительности, допускает
питание от батареи. При аварии планировщик делает до трёх повторов через минуту.
Установка той же сборки повторяема; чужая задача или иной EXE не затираются.

CLI: без аргументов — фон, `--status` — JSON в stdout (читать с перенаправлением
или через `System.Diagnostics.Process`), `--stop` — возврат настройки и остановка.
`--exercise-stop` / `--exercise-crash` — только тестовые двухсекундные режимы.

Удаление автозапуска (не затрагивает CapsLang):

```powershell
$guard = "$env:LOCALAPPDATA\CapsLang\MwbSaverGuard\CapsLangMwbSaverGuard.exe"
Start-Process -FilePath $guard -ArgumentList '--stop' -Wait
Unregister-ScheduledTask -TaskName 'CapsLang MWB Screensaver Guard' -Confirm:$false
```

EXE можно сохранить для повторного запуска; удалять рабочий CapsLang не нужно.

## Проверено 2026-10-04

На `4ERK-NB` и `4ERK-PC`: реальное приобретение override, нормальный возврат,
`TerminateProcess` родителя и восстановление watchdog, запрет второго экземпляра,
`--stop`. Снимки постоянных настроек заставки и `powercfg /query` совпали до/после.
После установки обе задачи Running/Limited, MWB=true, runtime screensaver=false,
profile ScreenSaveActive=1. Исходные тайм-ауты NB=900, PC=1500 секунд сохранены.
Полный визуальный простой до тайм-аута и реальное выключение MWB ещё не проверены.

SHA-256 проверенного/установленного EXE:
`5E9B80447CA21DABC0E4B677CBBAA7A44D87E331729F61786491F6E81C22606C`.

MWB восстановился после возвращения кабеля. Удалена только устаревшая
Name2IP-привязка `4ERK-PC 192.168.0.195` на NB; новое значение — пустое.
Оба имени успешно разрешаются, матрица PC сверху/NB снизу сохранена. Ключи
сопряжения не читались в вывод, не переносились и не менялись. Пользователь
подтвердил настоящий переход курсора и работу клавиатуры на ПК через MWB.
