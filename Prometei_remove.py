import os
import shutil
import re
import hashlib
import winreg
import socket
import logging

# Configurer le logging
log_directory = r"C:\temp"
log_file = os.path.join(log_directory, "delete_prometei.dat")

if not os.path.exists(log_directory):
    os.makedirs(log_directory)

logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def delete_file_if_hash_matches(file_path, expected_hash):
    if os.path.exists(file_path):
        file_hash = calculate_sha256(file_path)
        if file_hash == expected_hash:
            try:
                os.remove(file_path)
                logging.info(f"Fichier '{file_path}' a été supprimé avec succès.")
            except Exception as e:
                logging.error(f"Une erreur s'est produite lors de la suppression du fichier '{file_path}': {e}")
        else:
            logging.warning(f"Le hachage du fichier '{file_path}' ne correspond pas. Attendu: {expected_hash}, Obtenu: {file_hash}")
    else:
        logging.info(f"Le fichier '{file_path}' n'existe pas.")

def delete_directory(directory_path):
    if os.path.exists(directory_path):
        try:
            shutil.rmtree(directory_path)
            logging.info(f"Répertoire '{directory_path}' a été supprimé avec succès.")
        except Exception as e:
            logging.error(f"Une erreur s'est produite lors de la suppression du répertoire '{directory_path}': {e}")
    else:
        logging.info(f"Le répertoire '{directory_path}' n'existe pas.")

def kill_processes_by_name(process_name):
    try:
        # Exécuter la commande tasklist pour obtenir la liste des processus
        output = os.popen('tasklist /fo csv /nh').read()
        for line in output.splitlines():
            if process_name.lower() in line.lower():
                pid = int(line.split(',')[1].strip('" '))
                os.system(f"taskkill /PID {pid} /F")
                logging.info(f"Processus '{process_name}' (PID: {pid}) a été terminé.")
    except Exception as e:
        logging.error(f"Une erreur s'est produite lors de la tentative de terminer le processus '{process_name}': {e}")

def disable_lsass_dumps():
    try:
        # Ouvrir la clé de registre pour la modification
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", 0, winreg.KEY_SET_VALUE)
        
        # Définir les valeurs nécessaires pour empêcher les dumps de LSASS
        winreg.SetValueEx(key, "CrashOnAuditFail", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "DisableRestrictedAdmin", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "NoLmHash", 0, winreg.REG_DWORD, 1)
        
        # Définir RunAsPPL pour protéger LSASS
        winreg.SetValueEx(key, "RunAsPPL", 0, winreg.REG_DWORD, 1)

        # Fermer la clé de registre
        winreg.CloseKey(key)
        logging.info("Les paramètres du registre pour empêcher les dumps de LSASS ont été modifiés avec succès.")
    except Exception as e:
        logging.error(f"Une erreur s'est produite lors de la modification des paramètres du registre: {e}")

def modify_hosts_file(entries):
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    
    try:
        # Lire le contenu actuel du fichier hosts
        with open(hosts_path, 'r') as file:
            lines = file.readlines()
        
        # Ajouter les nouvelles entrées si elles ne sont pas déjà présentes
        with open(hosts_path, 'a') as file:
            for entry in entries:
                if not any(entry in line for line in lines):
                    file.write(entry + '\n')
                    logging.info(f"L'entrée '{entry}' a été ajoutée au fichier hosts.")
    except Exception as e:
        logging.error(f"Une erreur s'est produite lors de la modification du fichier hosts: {e}")

# Chemins des fichiers et leurs hachages SHA-256 attendus
files_to_check = {
    r"C:\Windows\winhlpx64.exe": "39b1042a5b02f3925141733c0f78b64f9fae71a37041c6acc9a9a4e70723a0f1",
    r"C:\Windows\zsvc.exe": "9e1c486cd23d1b164678b6b8df7678326aa0201adfd1f098e8d68438fc371529"
}

# Supprimer les fichiers si les hachages correspondent
for file_path, expected_hash in files_to_check.items():
    delete_file_if_hash_matches(file_path, expected_hash)

# Exécuter la fonction pour tuer les processus spécifiés
processes_to_kill = [
    "xsv",
    "rdpclip",
    "sqlhost",
    "winhlpx64"
]

for process_name in processes_to_kill:
    kill_processes_by_name(process_name)

# Modifier les paramètres du registre pour empêcher les dumps de LSASS
disable_lsass_dumps()

# Supprimer le répertoire C:\Windows\dell
delete_directory(r"C:\Windows\dell")

# Entrées à ajouter au fichier hosts
hosts_entries = [
    "127.0.0.1 23.148.145.237",
    "127.0.0.1 69.84.240.57",
    "127.0.0.1 103.40.123.34",
    "127.0.0.1 103.184.128.180",
    "127.0.0.1 103.184.128.244",
    "127.0.0.1 194.195.213.62",
    "127.0.0.1 211.232.48.65",
    "127.0.0.1 103.65.236.53",
    "127.0.0.1 177.73.237.55",
    "127.0.0.1 221.120.144.101",
    "127.0.0.1 p1.feefreepool.net",
    "127.0.0.1 p2.feefreepool.net",
    "127.0.0.1 p3.feefreepool.net",
    "127.0.0.1 gb7ni5rgeexdcncj.onion",
    "127.0.0.1 mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq.zero",
    "127.0.0.1 23.148.145.237",
    "127.0.0.1 69.84.240.57",
    "127.0.0.1 103.40.123.34",
    "127.0.0.1 194.195.213.62",
    "127.0.0.1 103.184.128.244",
    "127.0.0.1 211.232.48.65",
    "127.0.0.1 p2.feefreepool.net",
    "127.0.0.1 mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq.zero",
    "127.0.0.1 gb7ni5rgeexdcncj.onion",
    "127.0.0.1 mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq.b32.i2p"
]

# Modifier le fichier hosts
modify_hosts_file(hosts_entries)
