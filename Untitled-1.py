#† Pater noster, qui es in caelis, sanctificetur nomen Tuum. Adveniat regnum Tuum. Fiat voluntas Tua, sicut in caelo et in terra. Panem nostrum quotidianum da nobis hodie, et dimitte nobis debita nostra sicut et nos dimittimus debitoribus nostris. Et ne nos inducas in tentationem, sed libera nos a malo. Quoniam Tuum est regnum et virtus et gloria in saecula. Amen. †
# строка выше нужна чтобы импорт прошёл нормально, если вы уверены в том, что всё будет работать, то можно удалить
import base64
import binascii
import hashlib
import json
import math
import struct
import threading
import time
import re
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
#nie wiem co za importy, szukalem przez internet

from quasar_client import QuasarClient

client = QuasarClient.from_environment(timeout=5)
client.wait_for_simulation_start()
state = client.get_state()

#класс логгера, write () для важных сообщений, summary() для всякого говна типа датчиков чи ошибок
class MBLogger:
    MAX_DETAILS = 12

    def __init__(self, client):
        self._client = client
        self._lock = threading.Lock()
        self._summaries = {}

    def _emit(self, level, event_id, message, details):
        try:  
            details = dict(list(details.items())[:self.MAX_DETAILS])
            self._client.journal(level, event_id, str(message)[:300], **details)
        except Exception as exc:
            print("MB journal error:", type(exc).__name__, str(exc)[:120])  #пишет что за ошибка

    def write(self, level, event_id, message, **details):
        self._emit(level, event_id, message, details)      # вне лока

    def summary(self, key, level, event_id, template, reason=None, **details):
        now = time.monotonic()
        with self._lock:
            e = self._summaries.setdefault(
                key, {"count": 0, "last": None, "reasons": {}})
            e["count"] += 1
            if reason:
                e["reasons"][reason] = e["reasons"].get(reason, 0) + 1
            if e["last"] is not None and now - e["last"] < 1.0:
                return
            count, reasons = e["count"], e["reasons"]
            e["count"], e["reasons"], e["last"] = 0, {}, now
        msg = template.format(count=count)
        if reasons:
            msg += "; " + ", ".join("{}×{}".format(r, n) for r, n in reasons.items())
        self._emit(level, event_id, msg, details)          # вне лока


#==========================================================================================================================================================================================================================================================================================
#        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@
#          *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@  
#    %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+        
#  @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+      
#    %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+        
#      +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@  
#        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@
#      +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@  
#    %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+        
#  @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+      
#    %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+        
#          *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@  
#        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@
#==========================================================================================================================================================================================================================================================================================

puppi = MBLogger(client)

_VER_RE = re.compile(r"^\d+\.\d+\.\d+$") #число.число.число
def _ver(v): #минус мусор всякий
    v = str(v)
    if not _VER_RE.match(v): #ошибка формата
        raise ValueError("bad version")
    return tuple(int(p) for p in v.split(".")) # перевод в инт через точку

def _sig_ok(pub, sig_b64, payload):
    try:
        pub.verify(base64.b64decode(sig_b64), payload, ec.ECDSA(hashes.SHA256())) #base64 in bytes und keine error 
        return True
    except (InvalidSignature, binascii.Error, ValueError, TypeError):
        return False #If haben wir einen Problemen

def run_updates():

    identity = client.get_update_identity()     #получение идентичности  чтобы существовали device_pub_bytes, dispatcher_pub, hardware, installed
    #Ключи из get_update_identity()
   
  
    if identity.get("updatesAvailable", True) is False:  #пропускаем обновления только при False.
        print("CybP_02: обновления недоступны")
        return

    hardware = identity["hardware"]
    installed = {fw["module"]: fw["version"] for fw in identity["firmware"]}

    device_priv = X25519PrivateKey.from_private_bytes(
        base64.b64decode(identity["devicePrivateKey"]))
    device_pub_bytes = device_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    dispatcher_pub = serialization.load_pem_public_key(
        identity["dispatcherPublicKey"].encode())


    # цикл сеанс
    session = None
    for _ in range(20):  # проверка на подмену
        try:
            proposal = client.open_update_session()
        except Exception as exc:
            puppi.write("error", "CybP_02",
                        "Не удалось получить сеанс: {}".format(type(exc).__name__))
            return
        sid_log = str(proposal.get("sessionId", ""))[:64]

        try:
            dkey = base64.b64decode(proposal["dispatcherKey"])
            payload = "{}|{}|{}".format(proposal["sessionId"], dkey.hex(),  # {sessionId}|{dispatcherKey.hex()}|{deviceKey.hex()}
                                        device_pub_bytes.hex()).encode()
            ok = _sig_ok(dispatcher_pub, proposal["signature"], payload)
        except (KeyError, binascii.Error, ValueError, TypeError):
            ok = False  # неполное/мусорное предложение = подмена

        if ok:
            session = proposal
            break

        puppi.write("error", "CybP_02",
                    "Подменный сеанс {} отклонён: подпись не подтверждена".format(sid_log), 
                    sessionId=sid_log)                                                      
        try:
            client.reject_update(proposal.get("sessionId"), "session-signature-invalid") #отказ от обновлений 
        except Exception as exc:
            print("CybP_02: reject_update (сеанс) не удался:", type(exc).__name__)

    if session is None:
        puppi.write("error", "CybP_02", "Подлинный сеанс не получен за 20 попыток")
        return
    sid = session["sessionId"]
    puppi.write("info", "CybP_02", "Подлинный сеанс открыт", sessionId=str(sid)[:64])  

    try:
        disp_pub_key = X25519PublicKey.from_public_bytes( #Ключ канала (X25519+HKDF) и расшифровка манифеста
            base64.b64decode(session["dispatcherKey"]))     
        shared_secret = device_priv.exchange(disp_pub_key)     
        channel_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,                      #  HKDF-SHA256, длина 32,
            salt=sid.encode(),
            info=b"moonbase-update-channel-v1", # salt = sessionId (UTF-8), info = b"moonbase-update-channel-v1",
        ).derive(shared_secret)
        cipher = AESGCM(channel_key)

        mresp = client.get_update_manifest(sid)
        manifest_json = cipher.decrypt(
            base64.b64decode(mresp["nonce"]),
            base64.b64decode(mresp["ciphertext"]),
            "{}|manifest".format(sid).encode(),
        )
        packages = json.loads(manifest_json)["packages"]
    except Exception as exc:
        puppi.write("error", "CybP_02",
                    "Манифест не получен/не расшифрован: {}".format(type(exc).__name__),
                    sessionId=str(sid)[:64])
        return

    def check_package(pkg): #возвращает (причиначи None, sha256 расшифрованного образа).
        pid = pkg["id"]
        module = pkg["module"]
        version = pkg["version"]
        target = pkg["target"]
        expected_sha = pkg["sha256"]
        sig_b64 = pkg["signature"]

        resp = client.fetch_update(sid, pid)
        image = cipher.decrypt(
            base64.b64decode(resp["nonce"]),
            base64.b64decode(resp["ciphertext"]),
            "{}|{}".format(sid, pid).encode(),            # AAD = "{sid}|{id}"
        )

        #SHA-256 образа             lower если пришлёт хеш заглавными
        actual_sha = hashlib.sha256(image).hexdigest()
        if actual_sha != str(expected_sha).strip().lower():
            return "SHA-256 не совпадает", None

        #подпись                    без lower
        sig_payload = "{}|{}|{}|{}|{}".format(
            pid, module, version, target, expected_sha).encode()
        if not _sig_ok(dispatcher_pub, sig_b64, sig_payload):
            return "Подпись пакета не подтверждена", None

        #платформа
        if target != hardware:
            return "Целевая платформа не совпадает", None

        #версия строго новее (откат отклоняется)
        if _ver(version) <= _ver(installed.get(module, "0.0.0")):
            return "Версия не новее установленной", None

        return None, actual_sha

    # цикл пакетов
    for pkg in packages:

        is_dict = isinstance(pkg, dict)
        pid_log = str(pkg.get("id", "?"))[:64] if is_dict else "?"  #обрезанный как Нетаньяху 
        pid_api = pkg.get("id", "?") if is_dict else "?"            #полный для API

        reason, sha = None, None
        try:
            reason, sha = check_package(pkg)  # fetch+decrypt+4 проверки
        except Exception as exc:  # выброс неправильных пакетов
            reason = "Пакет не прошёл разбор ({})".format(type(exc).__name__)

        if reason:
            puppi.write("error", "CybP_02",
                        "Поддельный пакет {} отклонён: {}".format(pid_log, reason),
                        packageId=pid_log)
            try:
                client.reject_update(sid, reason, pid_api)
            except Exception as exc:
                print("CybP_02: reject_update (пакет) не удался:", type(exc).__name__)
        else:
            try:
                client.install_update(sid, pid_api, sha)  # ИД сессии, пакета и хэш
                client.wait_for_firmware()
            except Exception as exc:
                puppi.write("warning", "CybP_02",
                            "Сбой установки пакета {}: {}".format(pid_log, type(exc).__name__),
                            packageId=pid_log)
                continue  
            installed[pkg["module"]] = pkg["version"]
            puppi.write("info", "CybP_02", "Пакет {} установлен".format(pid_log),  
                        packageId=pid_log)

    puppi.write("info", "CybP_02", "Цикл обновлений завершён")


#==========================================================================================================================================================================================================================================================================================
#        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@
#          *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@  
#    %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+        
#  @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+      
#    %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+        
#      +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@  
#        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@
#      +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@        +@@@@@@@@@@  @@@@@@@@@@*     .@@  
#    %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+            %@@@@@- -@@@@@@@@@@  %@@@@@+        
#  @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+        @@@@@@+     .@@@@@@      *@@@@@+      
#    %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+            %@=     -@@@@@@@@@@      -@+        
#          *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@            *@@@@@@  @@@@@@.         .@@  
#        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@        =@@@@@%      @@@@@@-     =@@@@@@
#==========================================================================================================================================================================================================================================================================================

# CybP_05

def _const(name, default):
    try:
        return float(getattr(QuasarClient, name))
    except Exception:
        return float(default) #если клиента нет)

class MotorSanitizer:
    KINEMATIC_TOLERANCE_RPM = 0.15 #<------------------------------------------------------------tutaj gdy speed of wheel
    MAX_SEQ_AHEAD = 128
    FB_SEQ_WINDOW = 128
    FB_PERIOD_S = 0.05        #ОС приходит каждые 50мс
    FB_BASELINE_TTL_S = 2.0   #через столько секунд без принятых кадров эталон сбрасывается

    def __init__(self, logger):
        self._logger = logger
        self._lock = threading.Lock()

        self._rated = _const("RATED_RPM", 120.0)
        self._r = _const("WHEEL_RADIUS", 0.05)
        self._L = _const("YAW_ARM", 0.146)
        tpr = _const("TICKS_PER_REVOLUTION", 2048.0)
        self._max_tps = (self._rated / 60.0) * tpr  # макс тиков/с на номинале

        self._last_cmd_seq = None
        self._last_fb_seq = None
        self._last_fb_time = None
        self._last_fb_ticks = None
        self._last_fb_frame = None

    #кадр команды
    def filter_command(self, frame, command):
        try:
            reason = self._check_command(frame, command)
        except Exception as exc:  # fail-closed
            reason = "Ошибка проверки: " + type(exc).__name__
        if reason:
            self._logger.summary("cmd-blocked", "warning", "CybP_05",
                                 "Заблокировано кадров команд: {count}", reason=reason)
        return reason

    # отправить команду
    def _check_command(self, frame, command):
        if not isinstance(frame, (bytes, bytearray)) or len(frame) != 16:
            return "Неверная длина кадра"
        frame = bytes(frame)
        if frame[0] != 0xA5 or frame[1] != 0x01:
            return "Неверный заголовок"
        if binascii.crc_hqx(frame[:14], 0xFFFF) != struct.unpack_from("<H", frame, 14)[0]:
            return "CRC не совпадает"

        rpms = [v / 10.0 for v in struct.unpack_from("<4h", frame, 4)]  # 4 x int16 в 0,1 об/мин
        for rpm in rpms:
            if abs(rpm) > self._rated:
                return "Скорость колеса превышает номинал"

        vals = [float(command.get(k, 0.0)) for k in ("x", "y", "angular")]
        if not all(math.isfinite(v) for v in vals):
            return "Нечисловая команда"

        vx, vy, omega = vals
        r, L = self._r, self._L
        expected_rad_s = [
            (vx - vy - L * omega) / r,  # FL
            (vx + vy + L * omega) / r,  # FR
            (vx + vy - L * omega) / r,  # RL
            (vx - vy + L * omega) / r,  # RR
        ]
        expected_rpms = [v * 60.0 / (2.0 * math.pi) for v in expected_rad_s]

        for i in range(4):
            if not abs(rpms[i] - expected_rpms[i]) <= self.KINEMATIC_TOLERANCE_RPM:  # not <= NaN тоже блокируется
                return "Скорости колёс не соответствуют команде"

        seq = frame[2]
        with self._lock:
            # seq проверяется последним и запоминается только у годного кадра
            if self._last_cmd_seq is not None:
                diff = (seq - self._last_cmd_seq) % 256
                if diff == 0 or diff > self.MAX_SEQ_AHEAD:
                    return "seq не впереди последнего кадра"
            self._last_cmd_seq = seq

        return None

    def validate_feedback(self, hex_string):    # проверка кадров обратной связи
                                                # Возвращает {"seq","ticks","temperature_c"} или None
        try:
            data, reason = self._check_feedback(hex_string)
        except Exception as exc:  # fail-closed
            data, reason = None, "Ошибка проверки ОС ({})".format(type(exc).__name__)
        if data is None and reason != "dup":
            self._logger.summary("fb-rejected", "warning", "CybP_05",
                                 "Отброшено кадров обратной связи: {count}", reason=reason)
        return data

    def _check_feedback(self, hex_string):
        try:
            frame = bytes.fromhex(hex_string)
        except (ValueError, TypeError):
            return None, "Не hex"

        if len(frame) != 24:
            return None, "Неверная длина кадра ОС"
        if frame[0] != 0xA5 or frame[1] != 0x02:
            return None, "Неверный заголовок ОС"
        if binascii.crc_hqx(frame[:22], 0xFFFF) != struct.unpack_from("<H", frame, 22)[0]:
            return None, "CRC ОС не совпадает"

        temperature_c = struct.unpack_from("<h", frame, 20)[0] / 10.0
        if not (-40.0 <= temperature_c <= 120.0):
            return None, "Температура вне диапазона"

        seq = frame[2]
        ticks = struct.unpack_from("<4i", frame, 4)
        now = time.monotonic()

        with self._lock:
            #Эталон устарел (или его ещё нет) -> принимаем кадр как новый эталон.
            stale = (self._last_fb_time is None
                     or now - self._last_fb_time > self.FB_BASELINE_TTL_S)

            if not stale:
                diff = (seq - self._last_fb_seq) % 256
                if diff == 0:
                    if frame == self._last_fb_frame:
                        return None, "dup"  # тот же кадр прочитан снова
                    return None, "seq повторён с другим содержимым"
                if diff > self.FB_SEQ_WINDOW:
                    return None, "seq позади последнего кадра"
                elapsed = max(now - self._last_fb_time, diff * self.FB_PERIOD_S)
                max_delta = self._max_tps * elapsed * 1.5 + 8  # +8 тиков: запас
                for i in range(4):
                    if abs(ticks[i] - self._last_fb_ticks[i]) > max_delta:
                        return None, "Скачок тиков выше возможного"

            self._last_fb_seq = seq
            self._last_fb_time = now
            self._last_fb_ticks = ticks
            self._last_fb_frame = frame
        return {"seq": seq, "ticks": ticks, "temperature_c": temperature_c}, None


# Подключение
motor_sanitizer = MotorSanitizer(puppi)
client.motor_filter = motor_sanitizer.filter_command

try:
    run_updates()
except Exception as _exc:
    puppi.write("error", "CybP_02",
                "Цикл обновлений прерван: {}".format(type(_exc).__name__))
    print("CybP_02: цикл прерван:", repr(_exc))
