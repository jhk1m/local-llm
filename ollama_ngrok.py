import os
import time
import json
import requests
import subprocess
import logging
from typing import Optional, Dict
from pathlib import Path
from app_config import AppSecrets, AppSettings

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class DynamicConfigUpdater:
    def __init__(self):
        self.app_settings = AppSettings()
        self.app_secrets = AppSecrets()
        self.ngrok_process = None
        self.ollama_process = None
        
    def _get_ngrok_url(self, retries: int = 3, delay: float = 2) -> Optional[str]:
        """Get the public URL from ngrok"""
        for attempt in range(retries):
            try:
                response = requests.get(
                    "http://localhost:4040/api/tunnels",
                    timeout=2
                )
                tunnels = response.json().get("tunnels", [])
                if tunnels:
                    return tunnels[0]["public_url"]
            except Exception as e:
                if attempt < retries - 1:
                    time.sleep(delay)
                continue
        return None

    def _start_ngrok(self) -> None:
        """Start ngrok tunnel"""
        if self.ngrok_process is not None:
            self._stop_ngrok()
            
        ngrok_cmd = f"ngrok http 11434 --log stdout"
        self.ngrok_process = subprocess.Popen(
            ngrok_cmd.split(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(3)  # Give ngrok time to initialize

    def _stop_ngrok(self) -> None:
        """Stop ngrok process"""
        if self.ngrok_process:
            self.ngrok_process.terminate()
            try:
                self.ngrok_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.ngrok_process.kill()
            self.ngrok_process = None

    def _start_ollama(self) -> None:
        """Start Ollama server if not running"""
        try:
            requests.get("http://localhost:11434", timeout=2)
            print("✅ Ollama server already running")
        except:
            print("🚀 Starting Ollama server...")
            self.ollama_process = subprocess.Popen(
                ["ollama", "serve"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # Wait for Ollama to become responsive
            for _ in range(10):
                try:
                    if requests.get("http://localhost:11434", timeout=2).status_code == 200:
                        print("✅ Ollama server is ready")
                        return
                except:
                    time.sleep(1)
            raise RuntimeError("Failed to start Ollama server")

    def _load_ollama_model(self) -> None:
        """Ensure the specified model is loaded"""
        print(f"📦 Loading model: {self.app_secrets.OLLAMA_MODEL}...")
        try:
            response = requests.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": self.app_secrets.OLLAMA_MODEL,
                    "prompt": "ping",
                    "stream": False
                },
                timeout=30
            )
            if response.status_code != 200:
                raise RuntimeError(f"Model load failed: {response.text}")
            print("✅ Model loaded successfully")
        except Exception as e:
            raise RuntimeError(f"Failed to load model: {str(e)}")

    def _update_remote_config(self, ollama_url: str) -> None:
        """Update remote server configuration"""
        print("🔄 Updating remote configuration...")
        
        # Update the secrets object
        self.app_secrets.OLLAMA_URL = ollama_url
        
        try:
            # Update systemd service
            ssh_cmd = f"""
            sudo sed -i '/^OLLAMA_URL=/d' /etc/default/alexa-fastapi &&
            sudo sed -i '/^JWT_SECRET=/d' /etc/default/alexa-fastapi &&
            echo 'OLLAMA_URL={ollama_url}' | sudo tee -a /etc/default/alexa-fastapi &&
            echo 'JWT_SECRET={self.app_secrets.JWT_SECRET}' | sudo tee -a /etc/default/alexa-fastapi &&
            sudo systemctl daemon-reload &&
            sudo systemctl restart alexa-fastapi
            """
            subprocess.run([
                "ssh",
                "-i", self.app_secrets.SSH_KEY,
                f"{self.app_secrets.EC2_USER}@{self.app_secrets.EC2_HOST}",
                ssh_cmd
            ], check=True)

            verify_cmd = f"grep 'OLLAMA_URL={ollama_url}' /etc/default/alexa-fastapi"
            result = subprocess.run([
                "ssh", "-i", self.app_secrets.SSH_KEY,
                f"{self.app_secrets.EC2_USER}@{self.app_secrets.EC2_HOST}",
                verify_cmd
            ], capture_output=True)
            
            if result.returncode != 0:
                logger.error("Config update verification failed!")
                return False
                
            return True
        except Exception as e:
            logger.error(f"Remote update failed: {str(e)}")
            return False

    def _check_remote_health(self) -> bool:
        """Enhanced health check with detailed logging"""
        health_url = f"https://api.onebladesolutions.com/health"
        try:
            response = requests.get(health_url, timeout=10)
            if response.status_code == 200:
                return True
            else:
                logger.error(f"Health check failed with status {response.status_code}")
                logger.debug(f"Response: {response.text}")
        except Exception as e:
            logger.error(f"Health check connection failed: {str(e)}")
        return False

    def deploy(self) -> None:
        """Main deployment method"""
        try:
            # 1. Start required services
            self._start_ollama()
            self._load_ollama_model()
            self._start_ngrok()
            
            # 2. Get ngrok URL
            ollama_url = self._get_ngrok_url()
            if not ollama_url:
                raise RuntimeError("Failed to get ngrok URL")
            print(f"🌐 Ngrok URL: {ollama_url}")
            
            # 3. Update remote configuration
            self._update_remote_config(ollama_url)
            
            # 4. Verify deployment
            print("⏳ Waiting for remote service to restart...")
            time.sleep(5)
            
            if self._check_remote_health():
                print("✅ Deployment successful!")
            else:
                print("⚠️ Deployment completed but health check failed")
                
        except Exception as e:
            print(f"❌ Deployment failed: {str(e)}")
            raise
        finally:
            # Cleanup processes
            self._stop_ngrok()

if __name__ == "__main__":
    try:
        DynamicConfigUpdater().deploy()
    except KeyboardInterrupt:
        print("\nDeployment interrupted by user")
    except Exception as e:
        print(f"Fatal error during deployment: {str(e)}")
        exit(1)