#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import getpass
import os
import sys
import time
import socket
import shlex
import base64
import hashlib
import warnings
from pathlib import Path

# Silenciar deprecations molestos de cryptography (TripleDES)
warnings.filterwarnings("ignore", category=DeprecationWarning)

try:
    import yaml
    import paramiko
    from colorama import init as colorama_init, Fore, Style
except Exception as e:
    print("[X] Falta un paquete: instala con 'pip install paramiko pyyaml colorama'", file=sys.stderr)
    sys.exit(1)

# --- opcional: tqdm para una barra más pro ---
try:
    from tqdm import tqdm  # pip install tqdm
    _HAS_TQDM = True
except Exception:
    _HAS_TQDM = False

# ---------------------- UI / helpers ----------------------

colorama_init()

def c_ok(msg):    return f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}"
def c_info(msg):  return f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}"
def c_warn(msg):  return f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}"
def c_err(msg):   return f"{Fore.RED}[X]{Style.RESET_ALL} {msg}"
def c_title(msg): return f"{Style.BRIGHT}{msg}{Style.RESET_ALL}"

BANNER = rf"""
{Style.BRIGHT}{Fore.MAGENTA}         
    .___                  .__                       
  __| _/______  _  ______ |  |   ____   ____  ______
 / __ |/  _ \ \/ \/ /    \|  |  /  _ \ / ___\/  ___/
/ /_/ (  <_> )     /   |  \  |_(  <_> ) /_/  >___ \ 
\____ |\____/ \/\_/|___|  /____/\____/\___  /____  >
     \/                 \/           /_____/     \/       


        by m10sec (2025) - Flipador de Tools - m10sec@proton.me
        Descarga rápidamente tus logs para análisis

{Style.RESET_ALL}"""

def print_banner():
    print(BANNER)
    print(c_title("=== Remote Logs Retriever ==="))

def human_bool(b: bool) -> str:
    return "yes" if b else "no"

def _human_size(num):
    for unit in ["B","KB","MB","GB","TB"]:
        if num < 1024.0 or unit == "TB":
            return f"{num:.1f} {unit}"
        num /= 1024.0

# ---------------------- config / IO ----------------------

def load_config(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    data.setdefault("logs", [])
    data.setdefault("remote_tar_path", "/tmp/logs_bundle.tgz")
    data.setdefault("key_path", str(Path.home() / ".ssh" / "id_rsa"))
    # opcional: port, host_fingerprint
    return data

def merge_cli_over_config(cfg: dict, args) -> dict:
    # CLI tiene prioridad si se especifica
    if args.port: cfg["port"] = args.port
    if args.key: cfg["key_path"] = args.key
    if args.fingerprint: cfg["host_fingerprint"] = args.fingerprint
    if args.tar_name:
        # si pasan nombre, ajustamos remote_tar_path respetando directorio remoto
        remote = cfg.get("remote_tar_path", "/tmp/logs_bundle.tgz")
        remote_dir = str(Path(remote).parent)
        cfg["remote_tar_path"] = str(Path(remote_dir) / args.tar_name)
    return cfg

# ---------------------- SSH helpers  ----------------------

def ssh_connect(host: str, user: str, cfg: dict, verbose=False):
    key_path = os.path.expanduser(cfg.get("key_path", ""))
    expected_fp = cfg.get("host_fingerprint")  # e.g., "SHA256:abc123..."
    port = int(cfg.get("port", 22))

    client = paramiko.SSHClient()
    if expected_fp:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.load_system_host_keys()
    except Exception:
        pass

    pkey = None
    if key_path and os.path.exists(key_path):
        try:
            try:
                pkey = paramiko.RSAKey.from_private_key_file(key_path)
            except paramiko.PasswordRequiredException:
                pw = getpass.getpass("Passphrase de la clave RSA: ")
                pkey = paramiko.RSAKey.from_private_key_file(key_path, password=pw)
        except Exception as e:
            if verbose:
                print(c_warn(f"No se pudo cargar clave {key_path}: {e}"))
            pkey = None

    try:
        if verbose:
            print(c_info(f"Conectando a {host}:{port} como {user} (clave: {human_bool(bool(pkey))})"))
        client.connect(
            hostname=host,
            port=port,
            username=user,
            pkey=pkey,
            timeout=15,
            allow_agent=True,
            look_for_keys=True,
        )
        # Mantener viva la sesión (evita timeouts en descargas largas, reciém agregado para evitar timeout)
        transport = client.get_transport()
        if transport is not None:
            transport.set_keepalive(30)  
    except paramiko.AuthenticationException:
        print(c_warn("Autenticación por clave falló. Intentando con contraseña..."))
        password = getpass.getpass("Contraseña SSH: ")
        client.connect(
            hostname=host,
            port=port,
            username=user,
            password=password,
            timeout=15,
            allow_agent=False,
            look_for_keys=False,
        )
        transport = client.get_transport()
        if transport is not None:
            transport.set_keepalive(30)
    except (socket.timeout, socket.error) as e:
        print(c_err(f"No se pudo conectar a {host}:{port} -> {e}"))
        raise
    except Exception as e:
        print(c_err(f"Error de conexión SSH: {e}"))
        raise

    # Verificación de fingerprint (formato OpenSSH: "SHA256:xxxxx")
    if expected_fp:
        server_key = client.get_transport().get_remote_server_key()
        sha = hashlib.sha256(server_key.asbytes()).digest()
        actual_fp = "SHA256:" + base64.b64encode(sha).decode().rstrip("=")
        if actual_fp != expected_fp:
            client.close()
            raise ValueError(
                f"Fingerprint del host NO coincide.\n  Esperado: {expected_fp}\n  Actual:   {actual_fp}"
            )
        if verbose:
            print(c_ok(f"Fingerprint verificado: {actual_fp}"))

    return client

def run_cmd(ssh: paramiko.SSHClient, cmd: str, verbose=False):
    if verbose:
        print(c_info(f"SSH$ {cmd}"))
    stdin, stdout, stderr = ssh.exec_command(cmd)
    rc = stdout.channel.recv_exit_status()
    out = stdout.read().decode(errors="ignore")
    err = stderr.read().decode(errors="ignore")
    return rc, out, err

def remote_exists(ssh: paramiko.SSHClient, path: str, verbose=False) -> bool:
    rc, _, _ = run_cmd(ssh, f"test -e {shlex.quote(path)}", verbose=verbose)
    return rc == 0

def sftp_write_text(ssh: paramiko.SSHClient, remote_path: str, content: str):
    sftp = ssh.open_sftp()
    try:
        with sftp.file(remote_path, "w") as f:
            if not content.endswith("\n"):
                content = content + "\n"
            f.write(content)
    finally:
        sftp.close()

# ---------------------- Descarga reanudable ----------------------

def sftp_download(ssh: paramiko.SSHClient, remote_path: str, local_path: Path, verbose=False, retries: int = 6, chunk_size: int = 32768):
    """
    Descarga reanudable con SFTP.
    - Si el archivo local existe, continúa desde el offset.
    - Reintenta cuando el servidor corta la conexión (EOF/SSHException).
    - Muestra barra de progreso si tqdm está disponible.
    """
    attempt = 0
    last_err = None

    while attempt <= retries:
        try:
            sftp = ssh.open_sftp()
            # Tamaño remoto (si no existe, excepción)
            rstat = sftp.stat(remote_path)
            remote_size = getattr(rstat, "st_size", None)

            if verbose:
                print(c_info(f"Descargando vía SFTP: {remote_path} -> {local_path} (size: {remote_size} bytes)"))


            # Offset local si existe archivo parcial
            local_path.parent.mkdir(parents=True, exist_ok=True)
            offset = 0
            if local_path.exists():
                offset = local_path.stat().st_size
                if offset > (remote_size or 0):
                    # más grande que remoto: borramos y empezamos
                    if verbose:
                        print(c_warn("El archivo local es mayor que el remoto; reiniciando descarga."))
                    local_path.unlink()
                    offset = 0

            rf = sftp.open(remote_path, "rb")
            lf = open(local_path, "ab")

            try:
                if offset:
                    rf.seek(offset)

                # Preparar progreso, añadido para ver como vamos
                if _HAS_TQDM and remote_size:
                    bar = tqdm(
                        total=remote_size,
                        initial=offset,
                        unit="B",
                        unit_scale=True,
                        unit_divisor=1024,
                        desc="Descarga",
                        leave=True
                    )
                    def _update_bar(n):
                        bar.update(n)
                else:
                    bar = None
                    start = time.time()
                    last_shown = offset
                    def _print_progress(transferred_now):
                        nonlocal last_shown
                        last_shown += transferred_now
                        if remote_size:
                            pct = (last_shown / remote_size) * 100
                            speed = (last_shown - offset) / max(time.time() - start, 1e-6)
                            sys.stdout.write(
                                f"\rDescarga: {pct:6.2f}%  "
                                f"{_human_size(last_shown)} / {_human_size(remote_size)}  "
                                f"({_human_size(speed)}/s)"
                            )
                            sys.stdout.flush()
                        else:
                            sys.stdout.write(f"\rDescarga: {_human_size(last_shown)}")
                            sys.stdout.flush()

                # Loop de lectura
                while True:
                    data = rf.read(chunk_size)
                    if not data:
                        break
                    lf.write(data)
                    if _HAS_TQDM and remote_size:
                        _update_bar(len(data))
                    else:
                        _print_progress(len(data))

                if bar:
                    bar.close()
                else:
                    sys.stdout.write("\n")

                lf.flush()

                # Validar tamaño final
                if (remote_size is None) or (local_path.stat().st_size == remote_size):
                    
                    try:
                        lf.close()
                    except Exception:
                        pass
                    try:
                        rf.close()
                    except Exception:
                        pass
                    sftp.close()
                    return
                else:
                    raise IOError("Tamaño local no coincide con el remoto; se reintentará.")

            finally:
                try:
                    lf.close()
                except Exception:
                    pass
                try:
                    rf.close()
                except Exception:
                    pass
                try:
                    sftp.close()
                except Exception:
                    pass

        except (EOFError, paramiko.SSHException, socket.error) as e:
            # Conexión cortada; reintentar
            last_err = e
            attempt += 1
            if verbose:
                print()
                print(c_warn(f"Conexión SFTP cortada (intento {attempt}/{retries}). Reanudando en breve... Detalle: {e}"))
            time.sleep(min(5 * attempt, 30))
            continue
        except Exception as e:
            last_err = e
            break

    # Si llegamos aquí, falló definitivamente
    raise RuntimeError(f"Falló la descarga reanudable de {remote_path}: {last_err}")


def build_remote_tar(ssh: paramiko.SSHClient, log_paths: list, remote_tar_path: str, verbose=False, dry_run=False) -> None:
    # Filtrar rutas existentes
    existing = []
    missing = []
    for p in log_paths:
        q = (p or "").strip()
        if not q:
            continue
        if remote_exists(ssh, q, verbose=verbose):
            existing.append(q)
        else:
            missing.append(q)

    if missing and verbose:
        print(c_warn(f"Rutas no encontradas ({len(missing)}):"))
        for m in missing:
            print(f"  - {m}")

    if not existing:
        raise FileNotFoundError("Ninguna ruta de log existe en el servidor.")

    if dry_run:
        print(c_ok("Dry-run: no se creará el tar. Rutas detectadas:"))
        for e in existing:
            print(f"  - {e}")
        return

    # Crear archivo remoto con la lista de rutas
    ts = int(time.time())
    tmp_list = f"/tmp/logs_list_{ts}.txt"
    list_content = "\n".join(existing) + "\n"
    sftp_write_text(ssh, tmp_list, list_content)

    # Empaquetar (gzip nivel 1 para menos CPU en servidores cargados)
    tar_cmd = f"tar -czf {shlex.quote(remote_tar_path)} -T {shlex.quote(tmp_list)} --ignore-failed-read --gzip --force-local"
    rc, _, err = run_cmd(ssh, tar_cmd, verbose=verbose)

    # Limpiar la lista temporal del server 
    run_cmd(ssh, f"rm -f {shlex.quote(tmp_list)}", verbose=verbose)

    if rc != 0:
        raise RuntimeError(f"Fallo al crear tar.gz remoto: {err}")

def build_argparser() -> argparse.ArgumentParser:
    program_dir = Path(sys.argv[0]).resolve().parent
    epilog = f"""\
Ejemplos:
  # Usar config YAML y dejar la salida en la carpeta del programa
  %(prog)s -c logs_config.yaml --host 52.215.61.99 --user prosegur

  # Guardar en ~/Descargas con nombre personalizado
  %(prog)s -c logs_config.yaml --host 52.215.61.99 --user prosegur -o ~/Descargas --tar-name prosegur_logs.tgz

  # Puerto y clave específicos, modo verbose
  %(prog)s -c logs_config.yaml --host 52.215.61.99 --user prosegur --port 2222 --key ~/.ssh/id_work -v

  # Ver sólo qué rutas existen (no crea ni descarga nada)
  %(prog)s -c logs_config.yaml --host 52.215.61.99 --user prosegur --dry-run
"""
    ap = argparse.ArgumentParser(
        description="Empaqueta y descarga logs remotos por SSH usando un YAML de configuración.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=epilog
    )
    ap.add_argument("-c", "--config", required=True, help="Ruta al archivo YAML de configuración.")
    ap.add_argument("--host", help="IP/host del servidor (si no se pasa, se solicitará).")
    ap.add_argument("--user", help="Usuario SSH (si no se pasa, se solicitará).")
    ap.add_argument("--port", type=int, help="Puerto SSH (default: el del YAML o 22).")
    ap.add_argument("--key", help="Ruta a clave privada (default: la del YAML).")
    ap.add_argument("--fingerprint", help='Fingerprint del host en formato OpenSSH (ej: "SHA256:xxxxx").')
    ap.add_argument("-o", "--out", help=f"Directorio local de salida (default: carpeta del programa: {program_dir})")
    ap.add_argument("--tar-name", help="Nombre del .tgz remoto (default: el del YAML).")
    ap.add_argument("--no-clean", action="store_true", help="No borrar el .tgz remoto al finalizar.")
    ap.add_argument("--dry-run", action="store_true", help="No crear/descargar tar; solo listar rutas existentes.")
    ap.add_argument("-v", "--verbose", action="store_true", help="Salida detallada.")
    return ap

def main():
    print_banner()
    ap = build_argparser()
    args = ap.parse_args()

    cfg = load_config(Path(args.config))
    cfg = merge_cli_over_config(cfg, args)

    host = args.host or input("Host/IP: ").strip()
    user = args.user or input("Usuario SSH: ").strip()

    # Directorio de salida: por defecto, carpeta del programa
    program_dir = Path(sys.argv[0]).resolve().parent
    outdir = Path(args.out).expanduser().resolve() if args.out else program_dir
    outdir.mkdir(parents=True, exist_ok=True)

    # Conexión SSH
    try:
        ssh = ssh_connect(host, user, cfg, verbose=args.verbose)
    except Exception as e:
        print(c_err(f"No se pudo establecer conexión SSH: {e}"))
        sys.exit(2)

    try:
        logs = cfg.get("logs", [])
        if not logs:
            print(c_err("No hay rutas de logs en el YAML (clave 'logs')."))
            sys.exit(3)

        remote_tar = cfg.get("remote_tar_path", "/tmp/logs_bundle.tgz")
        print(c_info("Empaquetando logs en el servidor..."))
        build_remote_tar(ssh, logs, remote_tar, verbose=args.verbose, dry_run=args.dry_run)

        if args.dry_run:
            print(c_ok("Dry-run completado."))
            return

        # Nombre local: si no se especifica --tar-name, usamos logs_{host}.tgz localmente
        local_name = (args.tar_name if args.tar_name else f"logs_{host.replace(':','_')}.tgz")
        local_tar = outdir / local_name
        print(c_info(f"Descargando {remote_tar} -> {local_tar}"))
        sftp_download(ssh, remote_tar, local_tar, verbose=args.verbose)

        if not args.no_clean:
            run_cmd(ssh, f"rm -f {shlex.quote(remote_tar)}", verbose=args.verbose)

        print(c_ok(f"Listo. Archivo local: {local_tar}"))
    finally:
        ssh.close()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + c_warn("Interrumpido por el usuario."))
        sys.exit(130)