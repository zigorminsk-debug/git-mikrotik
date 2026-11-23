"""Windows desktop client for dispatching a reviewed RouterOS rule draft."""
import json
import re
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen
import webbrowser

REPO_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
WORKFLOW = "routeros-firewall.yml"


def dispatch(repository, ref, token, inputs):
    if not REPO_PATTERN.fullmatch(repository):
        raise ValueError("Репозиторий должен иметь вид owner/repository")
    if not ref.strip() or not token.strip():
        raise ValueError("Укажите ветку и GitHub token")
    owner, repo = repository.split("/")
    url = f"https://api.github.com/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/actions/workflows/{WORKFLOW}/dispatches"
    body = json.dumps({"ref": ref, "inputs": inputs}).encode("utf-8")
    request = Request(url, data=body, method="POST", headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "mikrotik-firewall-setup",
    })
    with urlopen(request, timeout=20) as response:
        if response.status != 204:
            raise RuntimeError(f"Неожиданный ответ GitHub: {response.status}")


def main():
    import tkinter as tk
    from tkinter import messagebox, ttk

    root = tk.Tk()
    root.title("MikroTik — GitHub Actions")
    root.geometry("660x620")
    root.minsize(600, 580)
    form = ttk.Frame(root, padding=18)
    form.pack(fill="both", expand=True)
    ttk.Label(form, text="Черновик правила Firewall (RouterOS 7)", font=("Segoe UI", 15, "bold")).pack(anchor="w")
    ttk.Label(form, text="Runner создаст отключённое правило input. Проверьте его в Winbox перед включением.", wraplength=610).pack(anchor="w", pady=(5, 12))
    fields = {}
    def field(label, name, default="", secret=False, choices=None):
        row = ttk.Frame(form)
        row.pack(fill="x", pady=4)
        ttk.Label(row, text=label, width=25).pack(side="left")
        var = tk.StringVar(value=default)
        fields[name] = var
        if choices:
            widget = ttk.Combobox(row, textvariable=var, values=choices, state="readonly")
        else:
            widget = ttk.Entry(row, textvariable=var, show="*" if secret else "")
        widget.pack(side="left", fill="x", expand=True)
    field("GitHub owner/repository", "repository")
    field("Ветка с workflow", "ref", "main")
    field("GitHub token (не сохраняется)", "token", secret=True)
    field("Действие", "action", "drop", choices=("drop", "accept"))
    field("Протокол", "protocol", "tcp", choices=("tcp", "udp"))
    field("Порт назначения", "port", "22")
    field("Источник IPv4/CIDR", "source", "192.168.88.0/24")
    ttk.Label(form, text="Токен нужен только для запуска workflow. Доступ к роутеру и SSH-ключ настраиваются отдельно в GitHub Secrets и на runner; приложение их не запрашивает.", wraplength=610).pack(anchor="w", pady=12)
    status = ttk.Label(form, text="")
    status.pack(anchor="w", pady=5)

    def send():
        inputs = {k: fields[k].get().strip() for k in ("action", "protocol", "port", "source")}
        # The runner independently validates every field; never trust client-side validation.
        try:
            import ipaddress
            ipaddress.IPv4Network(inputs["source"], strict=False)
            if not re.fullmatch(r"[0-9]{1,5}", inputs["port"]) or not 1 <= int(inputs["port"]) <= 65535:
                raise ValueError("Порт должен быть числом от 1 до 65535")
        except ValueError as exc:
            messagebox.showerror("Проверьте данные", str(exc), parent=root)
            return
        if not messagebox.askyesno("Подтверждение", "Отправить задание на создание ОТКЛЮЧЁННОГО правила?\nПроверьте репозиторий и параметры перед отправкой.", parent=root):
            return
        try:
            dispatch(fields["repository"].get().strip(), fields["ref"].get().strip(), fields["token"].get().strip(), inputs)
        except HTTPError as exc:
            messagebox.showerror("Ошибка GitHub", f"HTTP {exc.code}. Проверьте токен, права Actions, репозиторий и ветку.", parent=root)
            return
        except (ValueError, URLError, TimeoutError, OSError, RuntimeError) as exc:
            messagebox.showerror("Ошибка", str(exc), parent=root)
            return
        status.config(text="Задание принято GitHub. Проверьте результат во вкладке Actions.")
        messagebox.showinfo("Отправлено", "GitHub принял запрос. Это не означает, что правило создано: проверьте журнал запуска Actions.", parent=root)

    ttk.Button(form, text="Создать отключённое правило", command=send).pack(anchor="w", pady=5)
    def open_actions():
        repo = fields["repository"].get().strip()
        if REPO_PATTERN.fullmatch(repo):
            webbrowser.open(f"https://github.com/{repo}/actions")
        else:
            messagebox.showerror("Ошибка", "Укажите репозиторий в виде owner/repository", parent=root)
    ttk.Button(form, text="Открыть GitHub Actions", command=open_actions).pack(anchor="w")
    root.mainloop()


if __name__ == "__main__":
    main()
