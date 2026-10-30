# Security policy

**English** · [Русский](#ru) · [中文](#zh) · [فارسی](#fa)

AWG Router runs as root on a VPN server and holds the keys of every client and exit,
so security reports are very welcome.

## Supported versions

Only the latest release gets fixes. Update with `awg-router update`; the panel shows
when a new version is out.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability. Report it privately instead:
open the [Security tab](https://github.com/r-slashslash/AWG-Router/security) of this
repository and press **Report a vulnerability**. Only the maintainer sees the report.

Write in English, Russian, Chinese or Persian, whichever is easier. A useful report says:

- the panel version (System tab, or `cat /opt/awg-router/app/version.py`);
- the mode: Amnezia container or AmneziaWG on the host, HTTPS or SSH tunnel;
- what an attacker can do and what they need for it (no access, a client config,
  the panel link, the panel password…);
- steps to reproduce.

This is a project maintained in spare time: expect a first answer within about a week.
A confirmed issue is fixed in a new version, noted in `CHANGELOG.md` and in the release
notes, and the reporter is credited if they want to be.

## Scope

In scope: the panel and its API, the public client page (`/s/…`), the installer
(`install.sh`), backup and restore, the nftables and routing rules the panel builds,
the `amnezia-awg2` container image the installer creates.

Out of scope: AmneziaWG itself, the AmneziaVPN apps, Docker and the operating system —
please report those to their own projects. Attacks that need root on the server are
out of scope too.

---

<a id="ru"></a>
<details>
<summary><b>Русский</b></summary>

AWG Router работает на VPN-сервере от root и хранит ключи всех клиентов и выходов, поэтому
сообщения об уязвимостях очень нужны.

**Версии.** Исправления выходят только для последнего релиза: `awg-router update`.

**Как сообщить.** Пожалуйста, **не создавайте публичный issue**. Откройте вкладку
[Security](https://github.com/r-slashslash/AWG-Router/security) репозитория и нажмите
**Report a vulnerability** — сообщение увидит только автор. Можно писать по-русски.
Укажите версию панели, режим (контейнер Amnezia или AmneziaWG на хосте, HTTPS или
SSH-туннель), что может сделать атакующий и что ему для этого нужно, и шаги для повторения.

Проект ведётся в свободное время: первый ответ — примерно в течение недели. Подтверждённая
проблема исправляется в новой версии и описывается в `CHANGELOG.md` и в заметках к релизу;
автора сообщения упомянем, если он захочет.

**Что входит:** панель и её API, публичная страница клиента (`/s/…`), установщик,
резервная копия и восстановление, правила nftables и маршрутизации, образ контейнера
`amnezia-awg2`, который создаёт установщик. **Не входит:** сам AmneziaWG, приложения
AmneziaVPN, Docker и ОС, а также атаки, которым нужен root на сервере.

</details>

<a id="zh"></a>
<details>
<summary><b>中文</b></summary>

AWG Router 以 root 身份运行在 VPN 服务器上，保存着所有客户端和出口的密钥，因此非常欢迎安全报告。

**支持的版本：** 只有最新版本会得到修复，请用 `awg-router update` 更新。

**如何报告：** 请**不要提交公开 issue**。打开本仓库的
[Security](https://github.com/r-slashslash/AWG-Router/security) 页面，点击
**Report a vulnerability**，只有维护者能看到报告。可以用中文书写。请写明面板版本、运行模式
（Amnezia 容器或主机上的 AmneziaWG，HTTPS 或 SSH 隧道）、攻击者能做什么以及需要什么条件，
以及复现步骤。

这是业余时间维护的项目：通常在一周左右内首次回复。确认的问题会在新版本中修复，并写入
`CHANGELOG.md` 和发布说明；如报告者愿意，会注明致谢。

**范围内：** 面板及其 API、客户端公开页面（`/s/…`）、安装脚本、备份与恢复、面板生成的
nftables 和路由规则、安装脚本创建的 `amnezia-awg2` 容器镜像。**范围外：** AmneziaWG 本身、
AmneziaVPN 应用、Docker 和操作系统，以及需要服务器 root 权限的攻击。

</details>

<a id="fa"></a>
<details>
<summary><b>فارسی</b></summary>

<div dir="rtl">

‏AWG Router با دسترسی root روی سرور VPN اجرا می‌شود و کلیدهای همهٔ کلاینت‌ها و خروجی‌ها را نگه می‌دارد،
پس گزارش‌های امنیتی بسیار ارزشمندند.

**نسخه‌ها:** فقط آخرین نسخه اصلاح می‌شود؛ با `awg-router update` به‌روزرسانی کنید.

**روش گزارش:** لطفاً **issue عمومی باز نکنید**. زبانهٔ
[Security](https://github.com/r-slashslash/AWG-Router/security) مخزن را باز کنید و
**Report a vulnerability** را بزنید؛ گزارش را فقط نگه‌دارنده می‌بیند. می‌توانید فارسی بنویسید.
نسخهٔ پنل، حالت اجرا (کانتینر Amnezia یا AmneziaWG روی میزبان، HTTPS یا تونل SSH)، کاری که مهاجم
می‌تواند بکند و آنچه برایش لازم دارد، و مراحل بازتولید را بنویسید.

این پروژه در وقت آزاد نگه‌داری می‌شود: نخستین پاسخ معمولاً تا حدود یک هفته. مشکل تأییدشده در نسخهٔ
تازه رفع و در `CHANGELOG.md` و یادداشت انتشار ثبت می‌شود و اگر گزارش‌دهنده بخواهد، نامش آورده می‌شود.

**در محدوده:** پنل و API آن، صفحهٔ عمومی کلاینت (`/s/…`)، نصب‌کننده، پشتیبان‌گیری و بازیابی،
قوانین nftables و مسیریابی پنل، و ایمیج کانتینر `amnezia-awg2` که نصب‌کننده می‌سازد.
**خارج از محدوده:** خود AmneziaWG، برنامه‌های AmneziaVPN، Docker و سیستم‌عامل، و حمله‌هایی که به
دسترسی root روی سرور نیاز دارند.

</div>

</details>
