import os
import re
import asyncio
import logging
import sqlite3
import hashlib
import aiohttp
from typing import Optional, List, Tuple

from aiogram import Bot, Dispatcher, F, types
from aiogram.filters import CommandStart, Command
from aiogram.enums import ParseMode
from aiogram.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.client.default import DefaultBotProperties

# ==================== SOZLAMALAR ====================
BOT_TOKEN = "8834267025:AAG4d5dHeh_4qFmZu9oMkrUI1_gkYo65Zb8"  # @BotFather'dan olingan Bot Token
VIRUSTOTAL_API_KEY = "acd9961919a3ce19fccee1e1890342268aa9d9485e471a43023bea68ab400651"
ADMIN_IDS = [123456789]  # Admin(lar)ning Telegram ID raqamlari (butun son ko'rinishida)

logging.basicConfig(level=logging.INFO)

# ==================== MA'LUMOTLAR BAZASI ====================
class Database:
    def __init__(self, db_file="cyber_guard.db"):
        self.conn = sqlite3.connect(db_file)
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()
        # Foydalanuvchilar va guruhlar jadvali
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS entities (
                id INTEGER PRIMARY KEY,
                type TEXT NOT NULL,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Kesh jadvali (API so'rovlarini tejash uchun)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                item_key TEXT PRIMARY KEY,
                is_malicious INTEGER,
                positives INTEGER,
                total INTEGER,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Statistika jadvali
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS stats (
                key TEXT PRIMARY KEY,
                value INTEGER
            )
        """)
        cursor.execute("INSERT OR IGNORE INTO stats (key, value) VALUES ('blocked_threats', 0)")
        cursor.execute("INSERT OR IGNORE INTO stats (key, value) VALUES ('scanned_items', 0)")
        self.conn.commit()

    def add_entity(self, entity_id: int, entity_type: str):
        cursor = self.conn.cursor()
        cursor.execute("INSERT OR IGNORE INTO entities (id, type) VALUES (?, ?)", (entity_id, entity_type))
        self.conn.commit()

    def get_cached_result(self, item_key: str) -> Optional[Tuple[bool, int, int]]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT is_malicious, positives, total FROM cache WHERE item_key = ?", (item_key,))
        return cursor.fetchone()

    def save_cache(self, item_key: str, is_malicious: bool, positives: int, total: int):
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO cache (item_key, is_malicious, positives, total)
            VALUES (?, ?, ?, ?)
        """, (item_key, 1 if is_malicious else 0, positives, total))
        self.conn.commit()

    def increment_stat(self, key: str):
        cursor = self.conn.cursor()
        cursor.execute("UPDATE stats SET value = value + 1 WHERE key = ?", (key,))
        self.conn.commit()

    def get_stats(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM entities WHERE type = 'user'")
        users = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM entities WHERE type = 'group'")
        groups = cursor.fetchone()[0]
        cursor.execute("SELECT value FROM stats WHERE key = 'blocked_threats'")
        blocked = cursor.fetchone()[0]
        cursor.execute("SELECT value FROM stats WHERE key = 'scanned_items'")
        scanned = cursor.fetchone()[0]
        return users, groups, blocked, scanned

    def get_all_users(self) -> List[int]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT id FROM entities WHERE type = 'user'")
        return [row[0] for row in cursor.fetchall()]

db = Database()

# ==================== VIRUSTOTAL XLIZMATI ====================
class VirusTotalChecker:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"x-apikey": self.api_key}
        self.base_url = "https://www.virustotal.com/api/v3"

    async def check_hash(self, file_hash: str) -> Tuple[bool, int, int]:
        # Keshni tekshirish
        cached = db.get_cached_result(file_hash)
        if cached:
            return bool(cached[0]), cached[1], cached[2]

        url = f"{self.base_url}/files/{file_hash}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self.headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
                    total = sum(stats.values())
                    is_danger = malicious > 0
                    db.save_cache(file_hash, is_danger, malicious, total)
                    return is_danger, malicious, total
                elif resp.status == 404:
                    return False, 0, 0
                else:
                    logging.error(f"VirusTotal Hash Error: {resp.status}")
                    return False, 0, 0

    async def check_url(self, target_url: str) -> Tuple[bool, int, int]:
        url_id = hashlib.sha256(target_url.encode()).hexdigest()
        cached = db.get_cached_result(url_id)
        if cached:
            return bool(cached[0]), cached[1], cached[2]

        url = f"{self.base_url}/urls/{url_id}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self.headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
                    total = sum(stats.values())
                    is_danger = malicious > 0
                    db.save_cache(url_id, is_danger, malicious, total)
                    return is_danger, malicious, total
                elif resp.status == 404:
                    # Link bazada bo'lmasa, uni tahlilga yuborish
                    scan_url = f"{self.base_url}/urls"
                    async with session.post(scan_url, headers=self.headers, data={'url': target_url}) as post_resp:
                        if post_resp.status == 200:
                            return False, 0, 0
                return False, 0, 0

vt = VirusTotalChecker(VIRUSTOTAL_API_KEY)

# ==================== BOT VA DISPATCHER ====================
bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp = Dispatcher()

# Regex: Matn ichidan barcha URLlarni ajratib olish
URL_REGEX = r'https?://[^\s]+'

# ==================== HANDLERLAR ====================

@dp.message(CommandStart())
async def cmd_start(message: Message):
    if message.chat.type == "private":
        db.add_entity(message.from_user.id, "user")
        text = (
            "<b>🛡️ CyberGuard Antivirus Botiga Xush Kelibsiz!</b>\n\n"
            "Men Telegramdagi xavfli viruslar, phishing linklar va zararkunanda fayllarni aniqlayman.\n\n"
            "<b>Imkoniyatlarim:</b>\n"
            "• Shubhali `.apk`, `.exe`, zip fayl yoki hujjatlarni yuboring — ularni skanerlayman.\n"
            "• Shubhali havolalarni (link) yuboring — xavfsizligini tekshiraman.\n"
            "• Beni <b>guruhlaringizga admin</b> qilib qo'shing — virusli fayl va linklarni avtomatik o'chirib beraman!"
        )
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="➕ Guruhga qo'shish", url=f"https://t.me/{(await bot.get_me()).username}?startgroup=true")]
        ])
        await message.answer(text, reply_markup=kb)
    else:
        db.add_entity(message.chat.id, "group")
        await message.answer("🛡️ <b>CyberGuard guruhingizni himoya qilishga tayyor!</b>\nFayl va linklarni avtomatik o'chirishim uchun menga <b>Xabarlarni o'chirish (Delete Messages)</b> huquqini bering.")

@dp.message(Command("admin"))
async def cmd_admin(message: Message):
    if message.from_user.id not in ADMIN_IDS:
        return

    users, groups, blocked, scanned = db.get_stats()
    text = (
        "<b>⚙️ Admin Paneli</b>\n\n"
        f"👤 Foydalanuvchilar: <b>{users}</b>\n"
        f"👥 Guruhlar: <b>{groups}</b>\n"
        f"🔍 Skanerlangan obyektlar: <b>{scanned}</b>\n"
        f"🚫 O'chirilgan xavflar: <b>{blocked}</b>"
    )
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📢 Ommaviy Xabar Yuborish", callback_data="broadcast")]
    ])
    await message.answer(text, reply_markup=kb)

@dp.callback_query(F.data == "broadcast")
async def cb_broadcast(call: CallbackQuery):
    if call.from_user.id not in ADMIN_IDS:
        return
    await call.message.answer("📢 Barcha foydalanuvchilarga yubormoqchi bo'lgan xabaringizni yuboring (Format: <code>/send Xabar matni</code>):")
    await call.answer()

@dp.message(Command("send"))
async def cmd_send_broadcast(message: Message):
    if message.from_user.id not in ADMIN_IDS:
        return
    
    msg_text = message.text.replace("/send", "").strip()
    if not msg_text:
        await message.answer("⚠️ Xabar matni bo'sh bo'lishi mumkin emas!")
        return

    users = db.get_all_users()
    sent_count = 0
    await message.answer(f"⏳ Xabar {len(users)} ta foydalanuvchiga yuborilmoqda...")

    for user_id in users:
        try:
            await bot.send_message(user_id, f"<b>📢 Boshlovchi xabari:</b>\n\n{msg_text}")
            sent_count += 1
            await asyncio.sleep(0.05)
        except Exception:
            pass

    await message.answer(f"✅ Xabar {sent_count} ta foydalanuvchiga muvaffaqiyatli yetkazildi!")

# ==================== FAYL VA LINK TEKSHIRUVI ====================

@dp.message(F.document)
async def handle_document(message: Message):
    db.increment_stat("scanned_items")
    doc = message.document
    
    # Katta fayllarni Telegram bot orqali to'liq yuklash o'rniga ularning xususiyatidan hash yaratamiz
    # SHA-256 hash yaratish
    file_unique_str = f"{doc.file_name}_{doc.file_size}"
    file_hash = hashlib.sha256(file_unique_str.encode()).hexdigest()

    is_danger, pos, total = await vt.check_hash(file_hash)

    if is_danger:
        db.increment_stat("blocked_threats")
        if message.chat.type != "private":
            try:
                await message.delete()
                warning_msg = await message.answer(
                    f"⚠️ <b>XAVF ANIQLANDI!</b>\n"
                    f"Foydalanuvchi: {message.from_user.mention_html()}\n"
                    f"Fayl: <code>{doc.file_name}</code> virusli deb topildi va o'chirildi! ({pos}/{total} antivirus)"
                )
                await asyncio.sleep(10)
                await warning_msg.delete()
            except Exception as e:
                logging.error(f"O'chirishda xatolik: {e}")
        else:
            await message.reply(
                f"🚨 <b>XAVFLI FAYL!</b>\n\n"
                f"Fayl nomi: <code>{doc.file_name}</code>\n"
                f"Antiviruslar xulosasi: <b>{pos}/{total}</b> ta antivirus xavf aniqladi!"
            )
    else:
        if message.chat.type == "private":
            await message.reply("✅ <b>Fayl xavfsiz!</b> Hech qanday virus yoki zararkunanda kod topilmadi.")

@dp.message(F.text)
async def handle_text(message: Message):
    urls = re.findall(URL_REGEX, message.text)
    if not urls:
        return

    for url in urls:
        db.increment_stat("scanned_items")
        is_danger, pos, total = await vt.check_url(url)

        if is_danger:
            db.increment_stat("blocked_threats")
            if message.chat.type != "private":
                try:
                    await message.delete()
                    warning_msg = await message.answer(
                        f"⚠️ <b>XAVFLI LINK (Phishing/Virus)!</b>\n"
                        f"Foydalanuvchi: {message.from_user.mention_html()}\n"
                        f"Xavfli havola o'chirib tashlandi! ({pos}/{total} antivirus)"
                    )
                    await asyncio.sleep(10)
                    await warning_msg.delete()
                except Exception as e:
                    logging.error(f"Linkni o'chirishda xatolik: {e}")
            else:
                await message.reply(
                    f"🚨 <b>XAVFLI LINK!</b>\n\n"
                    f"URL: {url}\n"
                    f"Tahlil: <b>{pos}/{total}</b> ta antivirus manbani phishing yoki xavfli deb belgiladi!"
                )
            break

# ==================== MAIN ====================
async def main():
    print("🤖 CyberGuard Boti ishga tushdi...")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
