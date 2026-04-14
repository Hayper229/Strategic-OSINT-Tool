import os, re, time, json, socket, datetime
from flask import Flask, render_template, request, send_file
from flask_socketio import SocketIO, emit
import whois
import dns.resolver
import phonenumbers
from phonenumbers import geocoder, carrier
from PIL import Image
import pytesseract
import face_recognition
from astral import LocationInfo
from astral.sun import sun
from fake_useragent import UserAgent
from colorama import Fore, init

# Настройка Tesseract для Windows (раскомментируй и укажи свой путь)
# pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

init(autoreset=True)
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Структура папок
DIRS = ['targets', 'media']
for d in DIRS: os.makedirs(d, exist_ok=True)

class UltimateEngine:
    def __init__(self, content):
        self.content = content
        self.ua = UserAgent()
        self.db = {
            "core": {}, "net": {}, "geo": [], "web": {"nicks": []},
            "ocr_data": [], "faces": [], "matches": []
        }

    def log(self, tag, msg, status="INFO"):
        ts = time.strftime("%H:%M:%S")
        socketio.emit('log_event', {'ts': ts, 'tag': tag, 'msg': msg, 'status': status})
        color = Fore.GREEN if status == "OK" else Fore.YELLOW if status == "PROCESS" else Fore.CYAN
        print(f"{Fore.LIGHTBLACK_EX}[{ts}] {color}[{tag:^10}] {msg}")

    def process(self):
        # 1. Текстовый анализ
        self.log("CORE", "Извлечение сущностей из текста...", "PROCESS")
        self.db["core"]["fio"] = re.findall(r'\b[А-Я][а-я]+\s[А-Я][а-я]+(?:\s[А-Я][а-я]+)?\b', self.content)
        self.db["core"]["phones"] = re.findall(r'(?:\+7|8)[\s\-\(]*9[0-9]{2}[\s\-\)]*[0-9]{3}[\s\-]*[0-9]{2}[\s\-]*[0-9]{2}', self.content)
        self.db["core"]["emails"] = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', self.content)
        self.db["core"]["inn"] = re.findall(r'\b\d{10,12}\b', self.content)
        self.db["core"]["auto"] = re.findall(r'\b[АВЕКМНОРСТУХ]\d{3}[АВЕКМНОРСТУХ]{2}\d{2,3}\b', self.content)
        self.db["web"]["nicks"] = re.findall(r'@[\w\d_]{3,}', self.content)
        
        # 2. Сетевой анализ
        if self.db["core"]["emails"]:
            domain = self.db["core"]["emails"][0].split('@')[-1]
            self.log("NET", f"Анализ домена {domain}...", "PROCESS")
            try:
                w = whois.whois(domain)
                self.db["net"] = {"registrar": w.registrar, "org": w.org, "creation": str(w.creation_date)}
                self.log("NET", "Whois данные получены", "OK")
            except: pass

        # 3. Vision: Face Detection & OCR
        self.log("VISION", "Запуск визуального анализа (OCR/Faces)...", "PROCESS")
        media_files = [f for f in os.listdir('media') if f.lower().endswith(('jpg', 'jpeg', 'png'))]
        
        for fn in media_files:
            path = os.path.join('media', fn)
            # OCR
            try:
                text = pytesseract.image_to_string(Image.open(path), lang='rus+eng')
                if text.strip():
                    plates = re.findall(r'\b[А-Я][0-9]{3}[А-Я]{2}[0-9]{2,3}\b', text.upper())
                    self.db["ocr_data"].append({"file": fn, "text": text[:100], "plates": plates})
                    # Cross-Match Logic
                    for p in plates:
                        if p in str(self.db["core"]["auto"]):
                            m = f"MATCH: Госномер {p} найден на фото {fn} и в тексте!"
                            self.db["matches"].append(m)
                            self.log("MATCH", m, "OK")
            except: pass
            
            # Faces
            try:
                img = face_recognition.load_image_file(path)
                locs = face_recognition.face_locations(img)
                if locs:
                    self.db["faces"].append({"file": fn, "count": len(locs)})
                    self.log("FACE", f"Найдено лиц: {len(locs)} в {fn}", "OK")
            except: pass

        self.log("FINISH", "Анализ завершен. Отчет готов.", "OK")
        return self.db

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('start_scan')
def handle_scan(json_data):
    engine = UltimateEngine(json_data['content'])
    results = engine.process()
    emit('scan_complete', results)

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
