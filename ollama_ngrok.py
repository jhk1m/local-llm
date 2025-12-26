import os
import time
import socket
import requests
import subprocess
import logging
from typing import Optional
from app_config import AppSecrets, AppSettings

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

class DynamicConfigUpdater:
    def __init__(self):
        self.app_settings = AppSettings()
        self.app_secrets = AppSecrets()
        self.ngrok_process: Optional[subprocess.Popen] = None
        self.ollama_process: Optional[subprocess.Popen] = None

    # ---------- Local ----------
    def _start_ollama(self) -> None:
        try:
            if requests.get("http://localhost:11434", timeout=2).status_code == 200:
                logger.info("Ollama server already running")
                return
        except requests.RequestException:
            pass

        logger.info("Starting Ollama server...")
        self.ollama_process = subprocess.Popen(
            ["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        for _ in range(20):
            try:
                if requests.get("http://localhost:11434", timeout=2).status_code == 200:
                    logger.info("Ollama server is ready")
                    return
            except requests.RequestException:
                time.sleep(0.5)
        raise RuntimeError("Failed to start Ollama server")

    def _load_ollama_model(self) -> None:
        logger.info("Loading model: %s", self.app_secrets.OLLAMA_MODEL)
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": self.app_secrets.OLLAMA_MODEL, "prompt": "ping", "stream": False},
            timeout=30,
        )
        if r.status_code != 200:
            raise RuntimeError(f"Model load failed: {r.text}")
        logger.info("Model loaded successfully")

    def _start_ngrok(self) -> None:
        if self.ngrok_process is not None:
            self._stop_ngrok()
        logger.info("Starting ngrok tunnel to 11434...")
        self.ngrok_process = subprocess.Popen(
            ["ngrok", "http", "11434", "--log", "stdout"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        for _ in range(20):
            try:
                requests.get("http://localhost:4040/api/tunnels", timeout=1)
                break
            except requests.RequestException:
                time.sleep(0.5)

    def _stop_ngrok(self) -> None:
        if self.ngrok_process:
            self.ngrok_process.terminate()
            try:
                self.ngrok_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.ngrok_process.kill()
            self.ngrok_process = None

    def _get_ngrok_url(self, retries: int = 10, delay: float = 1.0) -> Optional[str]:
        for _ in range(retries):
            try:
                r = requests.get("http://localhost:4040/api/tunnels", timeout=2)
                r.raise_for_status()
                tunnels = r.json().get("tunnels", [])
                https = [t["public_url"] for t in tunnels if t.get("public_url", "").startswith("https")]
                http = [t["public_url"] for t in tunnels if t.get("public_url", "").startswith("http")]
                chosen = (https or http or [None])[0]
                if chosen:
                    return chosen
            except Exception:
                pass
            time.sleep(delay)
        return None

    # ---------- Remote ----------
    def _ssh(self, remote_cmd: str, check=True, capture_output=False) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                "ssh",
                "-i", self.app_secrets.SSH_KEY,
                "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=accept-new",
                f"{self.app_secrets.EC2_USER}@{self.app_secrets.EC2_HOST}",
                remote_cmd,
            ],
            check=check,
            capture_output=capture_output,
            text=True,
        )

    def _update_remote_config_and_nginx(self, ollama_url: str) -> None:
        logger.info("Updating remote config, restarting service, and reloading nginx...")
        jwt_secret = self.app_secrets.JWT_SECRET_KEY

        # Everything runs as root where it matters; temp lives next to the target.
        script = r"""
    set -euo pipefail

    # 1) Make a temp file in /etc/default as root
    tmp="$(sudo mktemp /etc/default/alexa-fastapi.XXXXXX)"

    # 2) Build the new env content (preserve any other lines)
    if [ -f /etc/default/alexa-fastapi ]; then
    # Read original as root, rewrite only the keys we manage
    sudo awk -v oll="__OLLAMA__" -v jwt="__JWT__" '
        BEGIN{f=0;j=0}
        /^OLLAMA_URL=/ {print "OLLAMA_URL="oll; f=1; next}
        /^JWT_SECRET_KEY=/ {print "JWT_SECRET_KEY="jwt; j=1; next}
        {print}
        END{
        if(!f) print "OLLAMA_URL="oll
        if(!j) print "JWT_SECRET_KEY="jwt
        }
    ' /etc/default/alexa-fastapi | sudo dd of="$tmp" status=none
    else
    # Fresh file
    printf 'OLLAMA_URL=%s\nJWT_SECRET_KEY=%s\n' "__OLLAMA__" "__JWT__" | sudo dd of="$tmp" status=none
    fi

    # 3) Atomically install and clean up
    sudo install -m 600 "$tmp" /etc/default/alexa-fastapi
    sudo rm -f "$tmp"

    # 4) Restart app service
    sudo systemctl daemon-reload
    sudo systemctl restart alexa-fastapi
    sudo systemctl is-active --quiet alexa-fastapi

    # 5) Nginx sanity (test, then reload or restart)
    if [ -f /etc/nginx/conf.d/alexa_fastapi.conf ]; then
    sudo nginx -t
    if ! sudo systemctl reload nginx; then
        sudo systemctl restart nginx
    fi
    fi

    # 6) Show listeners and ALPN
    echo "[Listeners]"
    sudo ss -ltnp | egrep ":80|:443" || true
    if command -v openssl >/dev/null 2>&1; then
    echo "[ALPN]"
    echo | openssl s_client -connect 127.0.0.1:443 -servername api.onebladesolutions.com -alpn "h2,http/1.1" 2>/dev/null | grep -i "ALPN protocol" || true
    fi
    """
        script = script.replace("__OLLAMA__", ollama_url).replace("__JWT__", jwt_secret)
        try:
            self._ssh(script, check=True, capture_output=False)
        except subprocess.CalledProcessError as e:
            logger.error("Remote update/reload failed (exit %s).", e.returncode)
            # show immediate journal tail to avoid blind debugging
            try:
                self._ssh("sudo journalctl -u alexa-fastapi -n 80 --no-pager", check=False, capture_output=False)
            except Exception:
                pass
            raise

    def _check_remote_health(self, attempts: int = 20, delay: float = 1.0) -> bool:
        url = "https://api.onebladesolutions.com/health"
        for i in range(attempts):
            try:
                r = requests.get(url, timeout=5)
                if r.status_code == 200:
                    return True
                logger.warning("Health check %d/%d: HTTP %s", i + 1, attempts, r.status_code)
            except requests.RequestException as e:
                logger.warning("Health check %d/%d failed: %s", i + 1, attempts, e)
            time.sleep(delay)
        return False

    def _dns_guard(self) -> None:
        try:
            resolved = socket.gethostbyname(self.app_secrets.EC2_HOST)
            logger.info("EC2_HOST %s resolves to %s", self.app_secrets.EC2_HOST, resolved)
        except Exception as e:
            logger.warning("Could not resolve %s: %s", self.app_secrets.EC2_HOST, e)

    # ---------- Orchestrate ----------
    def deploy(self) -> None:
        try:
            self._start_ollama()
            self._load_ollama_model()
            self._start_ngrok()

            ollama_url = self._get_ngrok_url()
            if not ollama_url or not ollama_url.startswith("https"):
                raise RuntimeError(f"Failed to get HTTPS ngrok URL, got: {ollama_url!r}")
            logger.info("Ngrok URL: %s", ollama_url)

            self._dns_guard()
            self._update_remote_config_and_nginx(ollama_url)

            if not self._check_remote_health():
                raise RuntimeError("Remote health check failed after restart")

            logger.info("Deployment successful")
        finally:
            self._stop_ngrok()


if __name__ == "__main__":
    try:
        DynamicConfigUpdater().deploy()
    except KeyboardInterrupt:
        print("\nDeployment interrupted by user")
    except Exception as e:
        print(f"Fatal error during deployment: {e}")
        raise
