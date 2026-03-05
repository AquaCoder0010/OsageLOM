import requests
import logging
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class TelegramNotifier:
    def __init__(self, bot_token: str = None, chat_id: str = None):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.enabled = bool(bot_token and chat_id)
        
        if not self.enabled:
            logger.info("Telegram notifications disabled")
        elif bot_token and chat_id:
            logger.info(f"Telegram notifications enabled (chat: {chat_id})")
    
    def send_message(self, message: str, parse_mode: str = None) -> bool:
        if not self.enabled:
            return False
        
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        
        data = {
            'chat_id': self.chat_id,
            'text': message
        }
        
        if parse_mode:
            data['parse_mode'] = parse_mode
        
        try:
            response = requests.post(url, data=data, timeout=10)
            if response.status_code != 200:
                logger.error(f"Telegram error {response.status_code}: {response.text}")
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Telegram send failed: {e}")
            return False
    
    def send_family_progress(self, family: str, current: int, target: int, 
                           total_downloaded: int, errors: int = 0) -> bool:
        pct = (current / target * 100) if target > 0 else 0
        
        message = (
            f"📥 *Download Progress*\n\n"
            f"*Family:* `{family}`\n"
            f"*Progress:* {current}/{target} ({pct:.1f}%)\n"
            f"*Total Downloaded:* {total_downloaded}\n"
            f"*Errors:* {errors}\n"
            f"`{datetime.now().strftime('%H:%M:%S')}`"
        )
        
        return self.send_message(message, parse_mode='Markdown')
    
    def send_summary(self, family_counts: dict, total: int, 
                    pending_extractions: int = 0) -> bool:
        message = (
            f"📊 *Dataset Summary*\n\n"
            f"*Total Samples:* {total}\n"
            f"*Pending Extraction:* {pending_extractions}\n\n"
            f"*By Family:*\n"
        )
        
        for family, count in sorted(family_counts.items()):
            message += f"  • {family}: {count}\n"
        
        message += f"\n`{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
        
        return self.send_message(message, parse_mode='Markdown')
    
    def send_error(self, error_message: str, family: str = None) -> bool:
        prefix = f"[{family}] " if family else ""
        
        message = (
            f"⚠️ *Error* {prefix}\n\n"
            f"```{error_message}```\n"
            f"`{datetime.now().strftime('%H:%M:%S')}`"
        )
        
        return self.send_message(message, parse_mode='Markdown')
    
    def send_complete(self, family: str, count: int) -> bool:
        message = (
            f"✅ *Family Complete*\n\n"
            f"*Family:* `{family}`\n"
            f"*Samples:* {count}\n"
            f"`{datetime.now().strftime('%H:%M:%S')}`"
        )
        
        return self.send_message(message, parse_mode='Markdown')
