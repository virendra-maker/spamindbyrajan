from flask import Flask, request, Response
import json
import threading
import requests
from google.protobuf.json_format import MessageToJson
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
from collections import OrderedDict
import danger_count_pb2
import danger_generator_pb2
from byte import Encrypt_ID, encrypt_api

app = Flask(__name__)

def load_tokens():
    try:
        with open("token_ind.json", "r") as f:
            return json.load(f)
    except:
        return None

def encrypt_message(plaintext_bytes):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext_bytes, AES.block_size)
    encrypted = cipher.encrypt(padded)
    return binascii.hexlify(encrypted).decode('utf-8')

def create_uid_protobuf(uid):
    msg = danger_generator_pb2.dev_generator()
    msg.saturn_ = int(uid)
    msg.garena = 1
    return msg.SerializeToString()

def enc(uid):
    pb = create_uid_protobuf(uid)
    return encrypt_message(pb)

def decode_player_info(binary):
    info = danger_count_pb2.xt()
    info.ParseFromString(binary)
    return info

def get_player_info(uid):
    tokens = load_tokens()
    if tokens is None:
        return None, None

    token = tokens[0]['token']
    url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"

    encrypted_uid = enc(uid)
    edata = bytes.fromhex(encrypted_uid)

    headers = {
        'User-Agent': "Dalvik/2.1.0",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB51"
    }

    response = requests.post(url, data=edata, headers=headers, verify=False, timeout=10)

    if response.status_code != 200:
        return None, None

    info = decode_player_info(response.content)
    data = json.loads(MessageToJson(info))

    account = data.get("AccountInfo", {})

    player_name = account.get("PlayerNickname", "Unknown")
    player_uid = account.get("UID", uid)

    return player_name, player_uid

def send_friend_request(uid, token, url, results, lock):
    try:
        encrypted_id = Encrypt_ID(uid)
        payload = f"08a7c4839f1e10{encrypted_id}1801"
        encrypted_payload = encrypt_api(payload)

        headers = {
            "Authorization": f"Bearer {token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB51",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0"
        }

        response = requests.post(url, data=bytes.fromhex(encrypted_payload), headers=headers, timeout=10)

        with lock:
            if response.status_code == 200:
                results['success'] += 1
            else:
                results['failed'] += 1

    except:
        with lock:
            results['failed'] += 1

@app.route("/send_requests", methods=["GET"])
def handle_friend_request():
    uid = request.args.get("uid")

    if not uid:
        return Response(json.dumps({"error": "uid required"}), mimetype="application/json")

    tokens = load_tokens()
    if tokens is None:
        return Response(json.dumps({"error": "Token file not found"}), mimetype="application/json")

    player_name, player_uid = get_player_info(uid)

    url = "https://client.ind.freefiremobile.com/RequestAddingFriend"

    results = {"success": 0, "failed": 0}
    lock = threading.Lock()
    threads = []

    for i in range(min(100, len(tokens))):
        token = tokens[i]['token']
        thread = threading.Thread(target=send_friend_request, args=(uid, token, url, results, lock))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    output = OrderedDict([
        ("PlayerName", player_name),
        ("UID", player_uid),
        #("Region", "IND"),
        ("Success", results["success"]),
        ("Failed", results["failed"]),
        ("Status", 1 if results["success"] > 0 else 2)
    ])

    return Response(json.dumps(output), mimetype="application/json")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)